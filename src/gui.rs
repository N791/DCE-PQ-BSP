use crossbeam_channel::{bounded, Receiver};
use eframe::egui;
use egui_plot::{Line, Plot, Points};
use glam::Vec3;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::aead_chain::{BlockCiphertext, ChunkingAead, SessionKey};
use crate::entropy::{ChaosConfig, EntropyMixer};
use crate::lattice_sig::{
    BlindMessage, BlindSignature, BlindingFactor, MockLatticeCrypto, PrivateKey, PublicKey,
    Signature,
};
use crate::protocol::{SessionContext, Signer, User};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PageState {
    Settings,
    TrajectoryGen,
    ProtocolExec,
    Results,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutionState {
    Idle,
    Running,
    Paused,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolStep {
    Init,
    KeyGen,
    AeadChunking,
    Blinding,
    Signing,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrajectoryMode {
    TimeSeries,
    PhasePortrait,
    Histogram,
    ThreeDimensions,
}

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub session_key_string: String,
    pub session_key_hex: String,
    pub session_nonce: [u8; 16],
    pub enable_replay_protection: bool,
    pub replay_window_secs: u64,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        let default_str = "MySecretSessionKey_2026".to_string();
        let default_hex = default_str
            .as_bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        Self {
            session_key_string: default_str,
            session_key_hex: default_hex,
            session_nonce: [0x11; 16],
            enable_replay_protection: true,
            replay_window_secs: 300,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub num_blocks: usize,
    pub parallel_threads: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            num_blocks: 100,
            parallel_threads: 4,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExecutionStats {
    pub keygen_ms: u128,
    pub aead_ms: u128,
    pub blinding_ms: u128,
    pub signing_ms: u128,
    pub unblinding_ms: u128,
    pub total_signatures: usize,
}

#[derive(Debug, Clone)]
pub enum TrajectoryMessage {
    Update(f64),
    Completed,
}

pub struct ProtocolGUI {
    current_page: PageState,
    chaos_config: ChaosConfig,
    crypto_config: CryptoConfig,
    protocol_config: ProtocolConfig,

    trajectory_data: Vec<f64>,
    trajectory_3d_points: Vec<Vec3>,
    trajectory_gen_state: ExecutionState,
    trajectory_thread_running: Arc<AtomicBool>,
    trajectory_rx: Option<Receiver<TrajectoryMessage>>,
    trajectory_rounds: usize,
    trajectory_current_round: Arc<AtomicUsize>,
    traj_visualization_mode: TrajectoryMode,
    rotation_angle: f32,

    protocol_step: ProtocolStep,
    protocol_state: ExecutionState,
    execution_stats: ExecutionStats,

    pk: Option<PublicKey>,
    sk: Option<PrivateKey>,
    user: Option<User<MockLatticeCrypto>>,
    signer: Option<Signer<MockLatticeCrypto>>,

    ciphertexts: Option<Vec<BlockCiphertext>>,
    blind_messages: Option<Vec<BlindMessage>>,
    blinding_factors: Option<Vec<BlindingFactor>>,
    blind_signatures: Option<Vec<BlindSignature>>,
    final_signatures: Option<Vec<Signature>>,

    log_messages: Vec<String>,
    input_text: String,
}

impl Default for ProtocolGUI {
    fn default() -> Self {
        Self {
            current_page: PageState::Settings,
            chaos_config: ChaosConfig::default(),
            crypto_config: CryptoConfig::default(),
            protocol_config: ProtocolConfig::default(),

            trajectory_data: Vec::new(),
            trajectory_3d_points: Vec::new(),
            trajectory_gen_state: ExecutionState::Idle,
            trajectory_thread_running: Arc::new(AtomicBool::new(false)),
            trajectory_rx: None,
            trajectory_rounds: 1000,
            trajectory_current_round: Arc::new(AtomicUsize::new(0)),
            traj_visualization_mode: TrajectoryMode::TimeSeries,
            rotation_angle: 0.0,

            protocol_step: ProtocolStep::Init,
            protocol_state: ExecutionState::Idle,
            execution_stats: ExecutionStats::default(),

            pk: None,
            sk: None,
            user: None,
            signer: None,
            ciphertexts: None,
            blind_messages: None,
            blinding_factors: None,
            blind_signatures: None,
            final_signatures: None,

            log_messages: vec!["系统就绪".to_string()],
            input_text: "块1：交易数据\n块2：身份证明\n块3：传感器指标".to_string(),
        }
    }
}

impl ProtocolGUI {
    fn log(&mut self, msg: &str) {
        self.log_messages.push(msg.to_string());
    }
    fn render_settings_page(&mut self, ui: &mut egui::Ui) {
    ui.heading("参数设置页面");
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        // 1. 加密与身份参数组
        ui.vertical(|ui| {
            ui.set_min_width(ui.available_width()); // 强制垂直布局占满宽度
            ui.group(|ui| {
                ui.set_min_width(ui.available_width()); // 确保方框边框撑开
                ui.label(egui::RichText::new("加密与身份参数").strong());
                
                ui.label("会话密钥 (字符串):");
                // 使用 f32::INFINITY 确保输入框占满方框宽度
                if ui.add(egui::TextEdit::singleline(&mut self.crypto_config.session_key_string)
                    .desired_width(f32::INFINITY)) 
                    .changed() 
                {
                    self.crypto_config.session_key_hex = self.crypto_config.session_key_string
                        .as_bytes().iter().map(|b| format!("{:02X}", b)).collect::<String>();
                }

                ui.add_space(8.0);
                ui.label("会话密钥 (十六进制自动计算):");
                // 修改为不可编辑的文本框格式，同时保持宽度一致
                ui.add(egui::TextEdit::multiline(&mut self.crypto_config.session_key_hex)
                    .desired_width(f32::INFINITY)
                    .interactive(false) // 设置为不可编辑，但可以选中复制
                    .font(egui::TextStyle::Monospace));

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("启用防重放保护:");
                    ui.checkbox(&mut self.crypto_config.enable_replay_protection, "");
                });

                ui.horizontal(|ui| {
                    ui.label("防重放窗口 (秒):");
                    ui.add(egui::Slider::new(&mut self.crypto_config.replay_window_secs, 60..=3600));
                    if ui.button("默认值").clicked() {
                        self.crypto_config.replay_window_secs = 300;
                    }
                });
            });
        });

        ui.add_space(10.0);

        // 2. 混沌参数配置组
        ui.vertical(|ui| {
            ui.set_min_width(ui.available_width());
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("混沌参数配置").strong());

                ui.horizontal(|ui| {
                    ui.label("初始状态 x₀:");
                    ui.add(egui::Slider::new(&mut self.chaos_config.initial_state, 0.0..=1.0).step_by(0.01));
                    if ui.button("默认").clicked() { self.chaos_config.initial_state = 0.12345; }
                });

                ui.horizontal(|ui| {
                    ui.label("混沌参数 μ:");
                    ui.add(egui::Slider::new(&mut self.chaos_config.mu, 3.0..=4.0).step_by(0.001));
                    if ui.button("默认").clicked() { self.chaos_config.mu = 4.0; }
                });

                ui.horizontal(|ui| {
                    ui.label("轨迹生成轮数:");
                    ui.add(egui::Slider::new(&mut self.trajectory_rounds, 100..=10000).step_by(100.0));
                });
            });
        });

        ui.add_space(10.0);

        // 3. 协议执行参数组
        ui.vertical(|ui| {
            ui.set_min_width(ui.available_width());
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("协议执行参数").strong());

                ui.label("数据块数量:");
                let slider_width = ui.available_width() - 120.0;
                ui.add_sized(
                    egui::vec2(slider_width, 20.0),
                    egui::Slider::new(&mut self.protocol_config.num_blocks, 1..=500000)
                );
                
                ui.horizontal(|ui| {
                    ui.label("精确输入:");
                    let mut blocks_str = self.protocol_config.num_blocks.to_string();
                    if ui.add(egui::TextEdit::singleline(&mut blocks_str).desired_width(100.0)).changed() {
                        if let Ok(val) = blocks_str.parse::<usize>() {
                            self.protocol_config.num_blocks = val.max(1).min(1_000_000);
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("并行线程数:");
                    ui.add(egui::Slider::new(&mut self.protocol_config.parallel_threads, 1..=16));
                });
            });
        });

        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if ui.button("保存配置并进入轨迹生成").clicked() {
                if let Some(user) = self.user.as_ref() {
                    user.entropy_mixer.set_config(self.chaos_config.clone());
                }
                self.current_page = PageState::TrajectoryGen;
                self.log("配置已保存，进入轨迹生成页面");
            }
            if ui.button("重置为默认值").clicked() {
                self.chaos_config = ChaosConfig::default();
                self.crypto_config = CryptoConfig::default();
                self.protocol_config = ProtocolConfig::default();
                self.log("所有参数已重置");
            }
        });
    });
}

    fn render_trajectory_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("混沌轨迹生成与可视化");
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.group(|ui| {
                ui.label("轨迹实时显示 (最近500个数据点)");
                self.render_trajectory_plot(ui);
            });

            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("开始生成").clicked() {
                    if self.trajectory_gen_state == ExecutionState::Idle {
                        self.start_trajectory_generation();
                    }
                }

                if ui.button("暂停").clicked() {
                    if self.trajectory_gen_state == ExecutionState::Running {
                        self.trajectory_gen_state = ExecutionState::Paused;
                        self.trajectory_thread_running
                            .store(false, Ordering::SeqCst);
                        self.log("轨迹生成已暂停");
                    }
                }

                if ui.button("停止").clicked() {
                    self.trajectory_thread_running
                        .store(false, Ordering::SeqCst);
                    self.trajectory_gen_state = ExecutionState::Idle;
                    self.trajectory_data.clear();
                    self.trajectory_3d_points.clear();
                    self.trajectory_current_round.store(0, Ordering::SeqCst);
                    self.trajectory_rx = None;
                    self.log("轨迹生成已停止並清除数据");
                }

                ui.label(format!(
                    "进度: {}/{}",
                    self.trajectory_current_round.load(Ordering::Relaxed),
                    self.trajectory_rounds
                ));
            });

            ui.horizontal(|ui| {
                ui.label("可视化模式:");
                ui.selectable_value(
                    &mut self.traj_visualization_mode,
                    TrajectoryMode::TimeSeries,
                    "时间序列",
                );
                ui.selectable_value(
                    &mut self.traj_visualization_mode,
                    TrajectoryMode::PhasePortrait,
                    "相位图",
                );
                ui.selectable_value(
                    &mut self.traj_visualization_mode,
                    TrajectoryMode::Histogram,
                    "直方图",
                );
                ui.selectable_value(
                    &mut self.traj_visualization_mode,
                    TrajectoryMode::ThreeDimensions,
                    "3D轨迹",
                );
            });

            ui.separator();
            if ui.button("进入协议执行页面").clicked() {
                self.trajectory_thread_running
                    .store(false, Ordering::SeqCst);
                self.trajectory_gen_state = ExecutionState::Idle;
                self.current_page = PageState::ProtocolExec;
                self.log("进入协议执行页面");
            }
        });
    }

    fn render_trajectory_plot(&mut self, ui: &mut egui::Ui) {
        if let Some(rx) = &self.trajectory_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    TrajectoryMessage::Update(value) => {
                        self.trajectory_data.push(value);

                        // 为3D模式构建3D点
                        if self.trajectory_data.len() >= 3 {
                            let n = self.trajectory_data.len();
                            if n >= 3 {
                                let x = self.trajectory_data[n - 3];
                                let y = self.trajectory_data[n - 2];
                                let z = self.trajectory_data[n - 1];

                                // 将3D点规范化到 [-1, 1] 范围
                                let point = Vec3::new(
                                    (x - 0.5) as f32 * 2.0,
                                    (y - 0.5) as f32 * 2.0,
                                    (z - 0.5) as f32 * 2.0,
                                );
                                self.trajectory_3d_points.push(point);

                                // 保持最大500个3D点
                                if self.trajectory_3d_points.len() > 500 {
                                    self.trajectory_3d_points.remove(0);
                                }
                            }
                        }

                        if self.trajectory_data.len() > 500 {
                            self.trajectory_data.remove(0);
                        }
                        self.trajectory_current_round
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    TrajectoryMessage::Completed => {
                        self.trajectory_gen_state = ExecutionState::Completed;
                        self.trajectory_thread_running
                            .store(false, Ordering::SeqCst);
                    }
                }
            }
        }

        // 自动旋转3D视图
        if self.traj_visualization_mode == TrajectoryMode::ThreeDimensions {
            self.rotation_angle += 0.01;
        }

        // 限制高度为300px，用于2D图表，3D轨迹单独处理
        let viz_height = match self.traj_visualization_mode {
            TrajectoryMode::ThreeDimensions => 350.0, // 3D模式稍大一些
            _ => 300.0,                               // 2D模式固定高度
        };

        ui.allocate_space(egui::Vec2::new(ui.available_width(), 0.0)); // 固定宽度但高度为0的占位符

        match self.traj_visualization_mode {
            TrajectoryMode::TimeSeries => {
                let points: Vec<[f64; 2]> = self
                    .trajectory_data
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| [i as f64, v])
                    .collect();

                let line = Line::new(points).fill(0.0);
                Plot::new("trajectory_plot")
                    .view_aspect(2.0)
                    .height(viz_height)
                    .show(ui, |plot_ui| plot_ui.line(line));
            }
            TrajectoryMode::PhasePortrait => {
                if self.trajectory_data.len() > 1 {
                    let points: Vec<[f64; 2]> = self
                        .trajectory_data
                        .windows(2)
                        .map(|w| [w[0], w[1]])
                        .collect();
                    Plot::new("phase_plot")
                        .view_aspect(1.0)
                        .height(viz_height)
                        .show(ui, |plot_ui| plot_ui.points(Points::new(points)));
                }
            }
            TrajectoryMode::Histogram => {
                if !self.trajectory_data.is_empty() {
                    let mut buckets = [0usize; 10];
                    for &v in &self.trajectory_data {
                        let idx = ((v * 10.0) as usize).min(9);
                        buckets[idx] += 1;
                    }
                    let points: Vec<[f64; 2]> = buckets
                        .iter()
                        .enumerate()
                        .map(|(i, &count)| [i as f64 * 0.1, count as f64])
                        .collect();
                    Plot::new("histogram")
                        .view_aspect(2.0)
                        .height(viz_height)
                        .show(ui, |plot_ui| plot_ui.points(Points::new(points)));
                }
            }
            TrajectoryMode::ThreeDimensions => {
                self.render_3d_trajectory(ui, viz_height);
            }
        }
    }

    fn render_3d_trajectory(&mut self, ui: &mut egui::Ui, height: f32) {
        // 使用固定的高度限制
        let (_id, canvas_rect) = ui.allocate_space(egui::Vec2::new(ui.available_width(), height));
        let painter = ui.painter_at(canvas_rect);

        let center = canvas_rect.center();
        let radius = (canvas_rect.width().min(canvas_rect.height()) * 0.4) as f32;

        // 创建旋转矩阵（绕Y轴和X轴旋转）
        let angle_y = self.rotation_angle;
        let angle_x = self.rotation_angle * 0.5;

        let cos_y = angle_y.cos();
        let sin_y = angle_y.sin();
        let cos_x = angle_x.cos();
        let sin_x = angle_x.sin();

        // 绘制坐标轴
        self.draw_3d_axes(&painter, center, radius, cos_y, sin_y, cos_x, sin_x);

        // 绘制轨迹点
        if !self.trajectory_3d_points.is_empty() {
            let mut prev_screen_pos = None;

            for (i, &point) in self.trajectory_3d_points.iter().enumerate() {
                // 应用Y轴旋转
                let rotated_y = Vec3::new(
                    point.x * cos_y - point.z * sin_y,
                    point.y,
                    point.x * sin_y + point.z * cos_y,
                );

                // 应用X轴旋转
                let rotated = Vec3::new(
                    rotated_y.x,
                    rotated_y.y * cos_x - rotated_y.z * sin_x,
                    rotated_y.y * sin_x + rotated_y.z * cos_x,
                );

                // 透视投影 (简单的平行投影加z抖动)
                let distance_factor = 1.0 + rotated.z * 0.2;
                let screen_x = center.x + rotated.x * radius * distance_factor;
                let screen_y = center.y + rotated.y * radius * distance_factor;

                let screen_pos = egui::pos2(screen_x, screen_y);

                // 绘制点，颜色根据轨迹进度渐变
                let color = egui::Color32::from_rgb(
                    (150 + (i * 100 / self.trajectory_3d_points.len().max(1)) as u8).min(255),
                    (100 + (i * 50 / self.trajectory_3d_points.len().max(1)) as u8).min(255),
                    200,
                );
                painter.circle_filled(screen_pos, 2.0, color);

                // 绘制连接线
                if let Some(prev_pos) = prev_screen_pos {
                    painter.line_segment([prev_pos, screen_pos], egui::Stroke::new(1.0, color));
                }

                prev_screen_pos = Some(screen_pos);
            }
        }

        // 在底部添加控制提示
        let hint_rect = egui::Rect::from_min_max(
            egui::pos2(canvas_rect.min.x, canvas_rect.max.y - 20.0),
            canvas_rect.max,
        );
        painter.text(
            hint_rect.center(),
            egui::Align2::CENTER_CENTER,
            format!(
                "🔄 自动旋转中 | 轨迹点数: {}",
                self.trajectory_3d_points.len()
            ),
            egui::FontId::default(),
            egui::Color32::WHITE,
        );
    }

    fn draw_3d_axes(
        &self,
        painter: &egui::Painter,
        center: egui::Pos2,
        radius: f32,
        cos_y: f32,
        sin_y: f32,
        cos_x: f32,
        sin_x: f32,
    ) {
        // X轴 (红色)
        let x_end = self.project_3d_to_2d(
            Vec3::new(1.0, 0.0, 0.0),
            center,
            radius,
            cos_y,
            sin_y,
            cos_x,
            sin_x,
        );
        painter.line_segment([center, x_end], egui::Stroke::new(1.5, egui::Color32::RED));
        painter.text(
            x_end + egui::vec2(5.0, 0.0),
            egui::Align2::LEFT_CENTER,
            "X",
            egui::FontId::default(),
            egui::Color32::RED,
        );

        // Y轴 (绿色)
        let y_end = self.project_3d_to_2d(
            Vec3::new(0.0, 1.0, 0.0),
            center,
            radius,
            cos_y,
            sin_y,
            cos_x,
            sin_x,
        );
        painter.line_segment(
            [center, y_end],
            egui::Stroke::new(1.5, egui::Color32::GREEN),
        );
        painter.text(
            y_end + egui::vec2(0.0, -10.0),
            egui::Align2::CENTER_BOTTOM,
            "Y",
            egui::FontId::default(),
            egui::Color32::GREEN,
        );

        // Z轴 (蓝色)
        let z_end = self.project_3d_to_2d(
            Vec3::new(0.0, 0.0, 1.0),
            center,
            radius,
            cos_y,
            sin_y,
            cos_x,
            sin_x,
        );
        painter.line_segment([center, z_end], egui::Stroke::new(1.5, egui::Color32::BLUE));
        painter.text(
            z_end + egui::vec2(5.0, -5.0),
            egui::Align2::LEFT_CENTER,
            "Z",
            egui::FontId::default(),
            egui::Color32::BLUE,
        );
    }

    fn project_3d_to_2d(
        &self,
        point: Vec3,
        center: egui::Pos2,
        radius: f32,
        cos_y: f32,
        sin_y: f32,
        cos_x: f32,
        sin_x: f32,
    ) -> egui::Pos2 {
        // 应用Y轴旋转
        let rotated_y = Vec3::new(
            point.x * cos_y - point.z * sin_y,
            point.y,
            point.x * sin_y + point.z * cos_y,
        );

        // 应用X轴旋转
        let rotated = Vec3::new(
            rotated_y.x,
            rotated_y.y * cos_x - rotated_y.z * sin_x,
            rotated_y.y * sin_x + rotated_y.z * cos_x,
        );

        // 透视投影
        let distance_factor = 1.0 + rotated.z * 0.2;
        let screen_x = center.x + rotated.x * radius * distance_factor;
        let screen_y = center.y + rotated.y * radius * distance_factor;

        egui::pos2(screen_x, screen_y)
    }

    fn render_protocol_exec_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("协议执行页面");
        ui.separator();

        ui.horizontal(|ui| {
            match self.protocol_state {
                ExecutionState::Idle => ui.label("状态: 空闲"),
                ExecutionState::Running => {
                    ui.label(egui::RichText::new("状态: 运行中").color(egui::Color32::BLUE))
                }
                ExecutionState::Paused => {
                    ui.label(egui::RichText::new("状态: 暂停").color(egui::Color32::YELLOW))
                }
                ExecutionState::Completed => {
                    ui.label(egui::RichText::new("状态: 完成").color(egui::Color32::GREEN))
                }
            };

            match self.protocol_step {
                ProtocolStep::Init => ui.label("步骤: 初始化"),
                ProtocolStep::KeyGen => ui.label("步骤: 密钥生成"),
                ProtocolStep::AeadChunking => ui.label("步骤: AEAD 分块"),
                ProtocolStep::Blinding => ui.label("步骤: 盲化"),
                ProtocolStep::Signing => ui.label("步骤: 签名"),
                ProtocolStep::Done => ui.label("步骤: 完成"),
            };
        });
        ui.separator();

        // 优化：数据块输入头部 (带统计和控制按钮)
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("数据块输入区:").strong());

            // 实时计算有效的数据块行数
            let valid_blocks = self
                .input_text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count();
            ui.label(format!("(当前识别到 {} 个数据块)", valid_blocks));

            // 将按钮靠右对齐
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("清空数据").clicked() {
                    self.input_text.clear();
                }
            });
        });

        egui::Frame::canvas(ui.style())
            .fill(ui.visuals().faint_bg_color)
            .rounding(4.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_source("data_block_input")
                    .max_height(200.0) // 限制最高 200 像素，超出则内部滚动，不会撑开整个页面
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.input_text)
                                .hint_text("请输入或生成数据块...")
                                .desired_width(f32::INFINITY) // 宽度撑满
                                .font(egui::TextStyle::Monospace),
                        );
                    });
            });

        ui.add_space(10.0);
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("初始化与密钥生成").clicked()
                && self.protocol_step == ProtocolStep::Init
            {
                self.execute_keygen();
            }

            if ui.button("AEAD 分块与链式加密").clicked()
                && self.protocol_step == ProtocolStep::KeyGen
            {
                self.execute_aead();
            }
        });

        ui.horizontal(|ui| {
            if ui.button("并行盲化").clicked() && self.protocol_step == ProtocolStep::AeadChunking
            {
                self.execute_blinding();
            }

            if ui.button("防重放与签名").clicked() && self.protocol_step == ProtocolStep::Blinding
            {
                self.execute_signing();
            }
        });

        ui.horizontal(|ui| {
            if ui.button("并行去盲").clicked() && self.protocol_step == ProtocolStep::Signing {
                self.execute_unblinding();
            }

            if ui.button("重置协议").clicked() {
                *self = ProtocolGUI {
                    current_page: PageState::ProtocolExec,
                    chaos_config: self.chaos_config.clone(),
                    crypto_config: self.crypto_config.clone(),
                    protocol_config: self.protocol_config.clone(),
                    ..Default::default()
                };
                self.log("协议已重置");
            }
        });

        ui.separator();
        ui.label(egui::RichText::new("执行日志").strong());
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                for log in &self.log_messages {
                    if log.contains("Error") || log.contains("error") {
                        ui.label(egui::RichText::new(log).color(egui::Color32::RED));
                    } else if log.contains("OK") || log.contains("ok") || log.contains("Success") {
                        ui.label(egui::RichText::new(log).color(egui::Color32::GREEN));
                    } else {
                        ui.label(log);
                    }
                }
            });

        ui.separator();
        if ui.button("查看结果").clicked() {
            self.current_page = PageState::Results;
        }
    }

    fn render_results_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("结果查看页面");
        ui.separator();
        ui.group(|ui| {
            ui.label(egui::RichText::new("性能统计").strong());

            // 将微秒转换为浮点数并除以 1000.0，显示 3 位小数
            ui.label(format!(
                "密钥生成耗时: {:.3} ms",
                self.execution_stats.keygen_ms as f64 / 1000.0
            ));
            ui.label(format!(
                "AEAD 加密耗时: {:.3} ms",
                self.execution_stats.aead_ms as f64 / 1000.0
            ));
            ui.label(format!(
                "盲化耗时: {:.3} ms",
                self.execution_stats.blinding_ms as f64 / 1000.0
            ));
            ui.label(format!(
                "签名耗时: {:.3} ms",
                self.execution_stats.signing_ms as f64 / 1000.0
            ));
            ui.label(format!(
                "去盲耗时: {:.3} ms",
                self.execution_stats.unblinding_ms as f64 / 1000.0
            ));

            ui.label(format!(
                "总签名数: {}",
                self.execution_stats.total_signatures
            ));
        });

        ui.separator();

        ui.group(|ui| {
            ui.label(egui::RichText::new("签名结果").strong());

            if let Some(sigs) = &self.final_signatures {
                let total_count = sigs.len();
                ui.label(format!("已生成签名总数: {}", total_count));

                // 如果超过1000条，给出性能提示
                if total_count > 1000 {
                    ui.label(
                        egui::RichText::new("为了保证界面流畅，下方仅展示前 1000 个条目")
                            .color(egui::Color32::KHAKI),
                    );
                }

                egui::ScrollArea::vertical()
                    .max_height(200.0)
                    .show(ui, |ui| {
                        // 核心逻辑：使用 .take(1000) 限制迭代次数
                        for (i, sig) in sigs.iter().take(1000).enumerate() {
                            // 取前16字节转为十六进制展示
                            let hex: String = sig
                                .0
                                .iter()
                                .take(16)
                                .map(|b| format!("{:02X}", b))
                                .collect();
                            ui.monospace(format!("[块 {}] 签名摘要: {}...", i + 1, hex));
                        }

                        if total_count > 1000 {
                            ui.add_space(5.0);
                            ui.label(
                                egui::RichText::new(format!(
                                    "...... 余下 {} 个签名已隐藏",
                                    total_count - 1000
                                ))
                                .italics()
                                .color(egui::Color32::GRAY),
                            );
                        }
                    });
            } else {
                ui.label("暂无签名数据，请先执行协议流程。");
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("返回参数设置").clicked() {
                self.current_page = PageState::Settings;
            }
            if ui.button("返回协议执行").clicked() {
                self.current_page = PageState::ProtocolExec;
            }
            // if ui.button("导出结果 (CSV)").clicked() {
            //     self.log("导出功能阶段不完整");
            // }
        });
    }
    fn execute_keygen(&mut self) {
        let start = std::time::Instant::now();
        let num_blocks = self.protocol_config.num_blocks;

        // 【核心优化】：防止海量数据卡死 UI
        if num_blocks <= 1000 {
            // 数据量小，正常在 UI 显示每一行
            let mut blocks = Vec::with_capacity(num_blocks);
            for i in 1..=num_blocks {
                blocks.push(format!("块{}：数据_{}", i, i));
            }
            self.input_text = blocks.join("\n");
        } else {
            // 数据量极大时，为了保证界面不卡死，只显示提示语
            self.input_text = format!(
            "【海量压力测试模式启动】\n\n系统已配置为处理 {} 个虚拟数据块。\n为保证 GUI 界面流畅，此处不渲染明文细节。\n请点击下一步，后台将直接在内存中生成并执行极速处理。", 
            num_blocks
        );
        }

        let (pk, sk) = MockLatticeCrypto::generate_keypair();
        self.pk = Some(pk.clone());
        self.sk = Some(sk.clone());

        let entropy_mixer = EntropyMixer::with_config(self.chaos_config.clone());

        self.user = Some(User {
            pk: pk.clone(),
            lattice_engine: MockLatticeCrypto,
            entropy_mixer,
        });

        self.signer = Some(Signer {
            sk,
            lattice_engine: MockLatticeCrypto,
        });

        self.execution_stats.keygen_ms = start.elapsed().as_micros();
        self.protocol_step = ProtocolStep::KeyGen;
        self.log(format!("密钥生成完成 - 准备处理 {} 个数据块", num_blocks).as_str());
    }

    fn execute_aead(&mut self) {
        let start = std::time::Instant::now();
        let session_key = SessionKey([0x42; 32]);
        let num_blocks = self.protocol_config.num_blocks;

        // 【核心优化】：构建海量待处理数据
        let messages: Vec<Vec<u8>> = if num_blocks <= 1000 {
            // 小于1000时，正常从文本框读取
            self.input_text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|line| line.as_bytes().to_vec())
                .collect()
        } else {
            // 大于1000时，使用并行迭代器极速生成内存虚拟数据
            use rayon::prelude::*;
            (0..num_blocks)
                .into_par_iter()
                .map(|i| {
                    format!(
                        "海量虚拟压力测试数据块_序列号_{}_附加随机填充内容以便测试",
                        i
                    )
                    .into_bytes()
                })
                .collect()
        };

        if let Ok(ctxs) = ChunkingAead::encrypt_and_chain(&session_key, messages) {
            self.ciphertexts = Some(ctxs.clone());
            self.execution_stats.aead_ms = start.elapsed().as_micros();
            self.protocol_step = ProtocolStep::AeadChunking;
            self.log(format!("成功，AEAD 完成，共 {} 个数据块", ctxs.len()).as_str());
        }
    }

    fn execute_blinding(&mut self) {
        let start = std::time::Instant::now();

        if let (Some(user), Some(ciphertexts)) = (&self.user, &self.ciphertexts) {
            let blind_data = user.prepare_blind_blocks(ciphertexts);

            let mut b_msgs = Vec::new();
            let mut b_factors = Vec::new();
            for (msg, factor, _) in blind_data {
                b_msgs.push(msg);
                b_factors.push(factor);
            }
            self.blind_messages = Some(b_msgs.clone());
            self.blinding_factors = Some(b_factors);

            self.execution_stats.blinding_ms = start.elapsed().as_micros();
            self.protocol_step = ProtocolStep::Blinding;
            self.log(format!("成功，盲化完成，共 {} 条消息", b_msgs.len()).as_str());
        }
    }

    fn execute_signing(&mut self) {
        let start = std::time::Instant::now();

        if let (Some(signer), Some(blind_msgs)) = (&self.signer, &self.blind_messages) {
            let context = SessionContext {
                session_id: "SESSION_GUI".to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                nonce: self.crypto_config.session_nonce,
            };

            if let Ok(sigs) = signer.sign_blocks(&context, blind_msgs) {
                self.blind_signatures = Some(sigs.clone());
                self.execution_stats.signing_ms = start.elapsed().as_micros();
                self.protocol_step = ProtocolStep::Signing;
                self.log(format!("成功，签名完成，共 {} 个签名", sigs.len()).as_str());
            }
        }
    }

    fn execute_unblinding(&mut self) {
        let start = std::time::Instant::now();

        if let (Some(user), Some(blind_sigs), Some(factors)) =
            (&self.user, &self.blind_signatures, &self.blinding_factors)
        {
            if let Ok(final_sigs) = user.unblind_signatures(blind_sigs, factors) {
                self.execution_stats.unblinding_ms = start.elapsed().as_micros();
                self.execution_stats.total_signatures = final_sigs.len();
                self.final_signatures = Some(final_sigs.clone());

                self.protocol_step = ProtocolStep::Done;
                self.protocol_state = ExecutionState::Completed;
                self.log(
                    format!(
                        "成功，去盲完成，共 {} 个签名",
                        final_sigs.len()
                    )
                    .as_str(),
                );
            }
        }
    }

    fn start_trajectory_generation(&mut self) {
        if self.trajectory_gen_state != ExecutionState::Idle {
            return;
        }

        let (tx, rx) = bounded(100);
        self.trajectory_rx = Some(rx);

        let rounds = self.trajectory_rounds;
        let chaos_config = self.chaos_config.clone();
        let running = Arc::clone(&self.trajectory_thread_running);

        running.store(true, Ordering::SeqCst);
        self.trajectory_gen_state = ExecutionState::Running;

        thread::spawn(move || {
            let mixer = EntropyMixer::with_config(chaos_config);
            for _ in 0..rounds {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                let (_, value) = mixer.chaos_simulate_once();
                let _ = tx.send(TrajectoryMessage::Update(value));
                thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = tx.send(TrajectoryMessage::Completed);
        });

        self.log("轨迹生成已启动");
    }
}

impl eframe::App for ProtocolGUI {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("nav_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_page, PageState::Settings, "参数设置");
                ui.selectable_value(&mut self.current_page, PageState::TrajectoryGen, "轨迹生成");
                ui.selectable_value(&mut self.current_page, PageState::ProtocolExec, "协议执行");
                ui.selectable_value(&mut self.current_page, PageState::Results, "结果查看");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.current_page {
            PageState::Settings => self.render_settings_page(ui),
            PageState::TrajectoryGen => self.render_trajectory_page(ui),
            PageState::ProtocolExec => self.render_protocol_exec_page(ui),
            PageState::Results => self.render_results_page(ui),
        });
    }
}
