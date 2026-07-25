mod app;
mod audit;
mod diff;
mod export;
mod voice;
mod watcher;

use app::MerkleApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Merkle Audit Explorer | File Integrity Platform")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_transparent(true)
            .with_active(true),
        ..Default::default()
    };

    eframe::run_native(
        "Merkle Audit Explorer",
        native_options,
        Box::new(|cc| Box::new(MerkleApp::new(cc))),
    )
}
