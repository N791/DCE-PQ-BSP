mod aead_chain;
mod entropy;
mod error;
mod lattice_sig;
mod protocol;
mod gui;

use eframe::egui;

fn main() {
    println!("正在启动可视化面板...");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([850.0, 600.0])
            .with_title("基于混沌系统的分块盲签名隐私保护协议设计演示"),
        ..Default::default()
    };
    
    let _ = eframe::run_native(
        "Protocol Demonstration",
        options,
        Box::new(|_cc| {
            setup_custom_fonts(&_cc.egui_ctx);
            Box::new(gui::ProtocolGUI::default())
        }), 
    );
}

/// 配置字体
fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    fonts.font_data.insert(
        "my_chinese_font".to_owned(),
        egui::FontData::from_static(include_bytes!("../fonts/msyh.ttf")), 
    );

    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "my_chinese_font".to_owned());

    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "my_chinese_font".to_owned());

    ctx.set_fonts(fonts);
}
