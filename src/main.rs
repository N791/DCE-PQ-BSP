// mod aead_chain;
// mod entropy;
// mod error;
// mod lattice_sig;
// mod protocol;
// mod tests;

// use aead_chain::{ChunkingAead, SessionKey};
// use entropy::EntropyMixer;
// use lattice_sig::MockLatticeCrypto;
// use protocol::{SessionContext, Signer, User};
// use std::time::{SystemTime, UNIX_EPOCH};

// fn main() {
//     println!("🛡️ 初始化混沌增强的抗量子盲签名系统...");

//     // 1. 系统初始化与格密钥生成
//     let (pk, sk) = MockLatticeCrypto::generate_keypair();
//     let lattice_engine = MockLatticeCrypto;

//     // 实例化实体
//     let user = User {
//         pk: pk.clone(),
//         lattice_engine: MockLatticeCrypto,
//         entropy_mixer: EntropyMixer::new(),
//     };

//     let signer = Signer {
//         sk,
//         lattice_engine,
//     };

//     // 2. 消息准备与 AEAD 分块
//     let session_key = SessionKey([0x42; 32]);
//     let raw_messages = vec![
//         b"Block 1: Transaction Data".to_vec(),
//         b"Block 2: Identity Proof".to_vec(),
//         b"Block 3: Sensor Metrics".to_vec(),
//     ];

//     println!("📦 正在进行 AEAD 分块与构建 Hash 链...");
//     let ciphertexts = ChunkingAead::encrypt_and_chain(&session_key, raw_messages).unwrap();

//     // 3. User 阶段: 生成混沌熵并盲化 (并行)
//     println!("🌪️ 注入混沌熵并执行格基盲化...");
//     let blind_data = user.prepare_blind_blocks(&ciphertexts);
    
//     // 提取出 blind_messages 和 factors
//     let mut blind_messages = Vec::new();
//     let mut blinding_factors = Vec::new();
//     for (msg, factor, _entropy) in blind_data {
//         blind_messages.push(msg);
//         blinding_factors.push(factor);
//     }

//     // 4. 构建防重放上下文
//     let context = SessionContext {
//         session_id: "SESSION_XYZ_999".to_string(),
//         timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
//         nonce: [0x11; 16],
//     };

//     // 5. Signer 阶段: 并行计算抗量子签名
//     println!("✍️ Signer 执行并行抗量子盲签名...");
//     let blind_signatures = signer.sign_blocks(&context, &blind_messages).unwrap();

//     // 6. User 阶段: 并行去盲
//     println!("🎭 User 执行并行去盲操作...");
//     let final_signatures = user.unblind_signatures(&blind_signatures, &blinding_factors).unwrap();

//     // 7. 验证
//     println!("✅ 最终获得 {} 个有效签名！系统流转成功。", final_signatures.len());
// }
mod aead_chain;
mod entropy;
mod error;
mod lattice_sig;
mod protocol;
mod tests;
mod gui; // 引入可视化模块

use eframe::egui;

fn main() {
    println!("正在启动可视化面板...");

    // 配置 eframe 窗口参数
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([850.0, 600.0])
            .with_title("基于混沌系统的分块盲签名隐私保护协议设计演示"),
        ..Default::default()
    };
    
    // 运行 GUI
    let _ = eframe::run_native(
        "Protocol Demonstration",
        options,
        // 🚀 修正点：去掉了 Ok()，直接返回 Box::new()
        Box::new(|_cc| {
            setup_custom_fonts(&_cc.egui_ctx);
            Box::new(gui::ProtocolGUI::default())
        }), 
    );
}

/// 配置支持中文的自定义字体
fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 加载你的中文字体文件
    // include_bytes! 会在编译时将字体文件直接打包进二进制程序中
    // 请确保路径指向你实际存放字体的相对路径
    fonts.font_data.insert(
        "my_chinese_font".to_owned(),
        egui::FontData::from_static(include_bytes!("../fonts/msyh.ttf")), 
    );

    // 将自定义字体设置为 Proportional（比例字体）的最高优先级，替换默认字体
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "my_chinese_font".to_owned());

    // 将自定义字体设置为 Monospace（等宽字体）的最高优先级
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "my_chinese_font".to_owned());

    // 将配置好的字体应用到 egui 的上下文中
    ctx.set_fonts(fonts);
}