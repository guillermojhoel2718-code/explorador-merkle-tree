use crate::audit::{
    spawn_tree_builder, AuditRecord, HashAlgorithm, Node, WorkerMessage,
};
use crate::diff::{compare_reports, TreeDiffResult};
use crate::export::{load_report_from_json, save_report_to_json, ExportedAuditReport};
use crate::voice::play_alert_sound;
use crate::watcher::{FileWatcher, WatcherMessage};

use eframe::egui;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum AppTab {
    Explorer,      // 🌳 Explorador Visual
    Traceability,  // 📜 Trazabilidad y Reportes (Diff + Log + Export JSON)
    Settings,      // ⚙️ Ajustes
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum NodeColorMode {
    ByExtension, // 🎨 Colores por Extensión de Archivo
    ByAge,       // ⏳ Colores por Antigüedad / Tiempo de Modificación
}

#[derive(Clone, Debug)]
pub struct UndoSnapshot {
    pub description: String,
    pub focused_root_id: Option<usize>,
    pub selected_node_id: Option<usize>,
    pub zoom_scale: f32,
    pub pan_offset: egui::Vec2,
    pub custom_positions: HashMap<usize, egui::Pos2>,
}

pub struct MerkleApp {
    nodes: Vec<Node>,
    selected_node_id: Option<usize>,
    focused_root_id: Option<usize>, // Adaptive Visual Root Focus
    is_loading: bool,
    progress: (usize, usize),
    compute_hashes_enabled: bool,
    hash_algorithm: HashAlgorithm,
    dark_mode: bool,
    color_mode: NodeColorMode,
    zoom_scale: f32,
    pan_offset: egui::Vec2,

    // Floating Drag & Drop positions for nodes (Notion style)
    custom_node_positions: HashMap<usize, egui::Pos2>,

    // Undo / Redo Stacks
    undo_stack: Vec<UndoSnapshot>,
    redo_stack: Vec<UndoSnapshot>,

    rx: Receiver<WorkerMessage>,
    tx: Sender<WorkerMessage>,

    watcher_rx: Receiver<WatcherMessage>,
    watcher_tx: Sender<WatcherMessage>,
    watcher: Option<FileWatcher>,
    watcher_active: bool,

    last_audit: Option<AuditRecord>,
    current_path: Option<PathBuf>,

    // Thresholds & Custom Colors
    threshold_red_hours: u64,
    threshold_yellow_hours: u64,
    threshold_green_days: u64,

    color_red: egui::Color32,
    color_yellow: egui::Color32,
    color_green: egui::Color32,
    color_old: egui::Color32,

    notification_msg: Option<(String, Instant)>,

    // Filter & Search
    search_query: String,
    filter_extension: String,
    filter_max_size_mb: f32,

    // Forensic Mode
    forensic_mode: bool,
    open_files_cache: HashMap<usize, bool>, // Open/locked by process status

    // Navigation Sensitivity Sliders & Smart Zoom
    pan_speed_mult: f32,
    zoom_speed_factor: f32,
    smart_zoom_focus_enabled: bool,

    // Debounce background reload on file watcher events
    pending_watcher_reload: Option<Instant>,

    // Tabs
    active_tab: AppTab,

    // Diff Feature
    diff_report_a: Option<ExportedAuditReport>,
    diff_report_b: Option<ExportedAuditReport>,
    diff_result: Option<TreeDiffResult>,

    // History Log Cache
    history_log_lines: Vec<String>,

    // Pending Move Confirmation Dialog
    pending_move_confirmation: Option<(usize, usize)>,

    // Startup Welcome Modal Dialog
    show_welcome_dialog: bool,
}

impl MerkleApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        egui_extras::install_image_loaders(&_cc.egui_ctx);

        let (tx, rx) = channel();
        let (watcher_tx, watcher_rx) = channel();

        let history_lines = Self::load_history_log();

        Self {
            nodes: Vec::new(),
            selected_node_id: None,
            focused_root_id: None,
            is_loading: false,
            progress: (0, 0),
            compute_hashes_enabled: true,
            hash_algorithm: HashAlgorithm::Sha256,
            dark_mode: false, // Clean light UI matching reference design
            color_mode: NodeColorMode::ByExtension,
            zoom_scale: 1.0_f32,
            pan_offset: egui::Vec2::ZERO,
            custom_node_positions: HashMap::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            rx,
            tx,
            watcher_rx,
            watcher_tx,
            watcher: None,
            watcher_active: false,
            last_audit: None,
            current_path: None,
            threshold_red_hours: 1,
            threshold_yellow_hours: 12,
            threshold_green_days: 7,
            color_red: egui::Color32::from_rgb(239, 68, 68),
            color_yellow: egui::Color32::from_rgb(245, 158, 11),
            color_green: egui::Color32::from_rgb(16, 185, 129),
            color_old: egui::Color32::from_gray(160),
            notification_msg: None,
            search_query: String::new(),
            filter_extension: String::new(),
            filter_max_size_mb: 500.0_f32,
            forensic_mode: false,
            open_files_cache: HashMap::new(),
            pan_speed_mult: 2.0_f32,
            zoom_speed_factor: 1.04_f32,
            smart_zoom_focus_enabled: true,
            pending_watcher_reload: None,
            active_tab: AppTab::Explorer,
            diff_report_a: None,
            diff_report_b: None,
            diff_result: None,
            history_log_lines: history_lines,
            pending_move_confirmation: None,
            show_welcome_dialog: true,
        }
    }

    fn load_history_log() -> Vec<String> {
        if let Ok(content) = fs::read_to_string("merkle_audit_ledger.log") {
            content.lines().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    pub fn push_undo_snapshot(&mut self, description: &str) {
        let snap = UndoSnapshot {
            description: description.to_string(),
            focused_root_id: self.focused_root_id,
            selected_node_id: self.selected_node_id,
            zoom_scale: self.zoom_scale,
            pan_offset: self.pan_offset,
            custom_positions: self.custom_node_positions.clone(),
        };
        self.undo_stack.push(snap);
        self.redo_stack.clear();
    }

    pub fn undo(&mut self) {
        if let Some(snap) = self.undo_stack.pop() {
            let current_snap = UndoSnapshot {
                description: "Redo state".to_string(),
                focused_root_id: self.focused_root_id,
                selected_node_id: self.selected_node_id,
                zoom_scale: self.zoom_scale,
                pan_offset: self.pan_offset,
                custom_positions: self.custom_node_positions.clone(),
            };
            self.redo_stack.push(current_snap);

            self.focused_root_id = snap.focused_root_id;
            self.selected_node_id = snap.selected_node_id;
            self.zoom_scale = snap.zoom_scale;
            self.pan_offset = snap.pan_offset;
            self.custom_node_positions = snap.custom_positions;

            self.set_notification(format!("↩ Deshecho: {}", snap.description));
        } else {
            self.set_notification("⚠️ No hay más acciones para deshacer".to_string());
        }
    }

    pub fn redo(&mut self) {
        if let Some(snap) = self.redo_stack.pop() {
            let current_snap = UndoSnapshot {
                description: "Undo state".to_string(),
                focused_root_id: self.focused_root_id,
                selected_node_id: self.selected_node_id,
                zoom_scale: self.zoom_scale,
                pan_offset: self.pan_offset,
                custom_positions: self.custom_node_positions.clone(),
            };
            self.undo_stack.push(current_snap);

            self.focused_root_id = snap.focused_root_id;
            self.selected_node_id = snap.selected_node_id;
            self.zoom_scale = snap.zoom_scale;
            self.pan_offset = snap.pan_offset;
            self.custom_node_positions = snap.custom_positions;

            self.set_notification("↪ Rehecho".to_string());
        }
    }

    pub fn load_directory(&mut self, path: PathBuf) {
        self.is_loading = true;
        self.progress = (0, 0);
        self.nodes.clear();
        self.selected_node_id = None;
        self.focused_root_id = None;
        self.zoom_scale = 1.0_f32;
        self.pan_offset = egui::Vec2::ZERO;
        self.custom_node_positions.clear();
        self.open_files_cache.clear();
        self.current_path = Some(path.clone());

        if self.watcher_active {
            self.start_watcher(path.clone());
        }

        spawn_tree_builder(
            path,
            self.compute_hashes_enabled,
            self.hash_algorithm,
            self.tx.clone(),
        );
    }

    pub fn reload_directory_background(&mut self) {
        if self.is_loading {
            return;
        }
        if let Some(ref path) = self.current_path.clone() {
            self.is_loading = true;
            self.progress = (0, 0);
            // DO NOT clear self.nodes or reset camera! Keep current tree visible and interactable.
            spawn_tree_builder(
                path.clone(),
                self.compute_hashes_enabled,
                self.hash_algorithm,
                self.tx.clone(),
            );
        }
    }

    fn start_watcher(&mut self, path: PathBuf) {
        match FileWatcher::start(path, self.watcher_tx.clone()) {
            Ok(w) => {
                self.watcher = Some(w);
                self.watcher_active = true;
                self.set_notification("👁️ Monitoreo en tiempo real activado".to_string());
            }
            Err(e) => {
                self.set_notification(format!("❌ Error iniciando watcher: {}", e));
                self.watcher_active = false;
            }
        }
    }

    fn stop_watcher(&mut self) {
        self.watcher = None;
        self.watcher_active = false;
        self.set_notification("⏹️ Monitoreo detenido".to_string());
    }

    fn set_notification(&mut self, msg: String) {
        self.notification_msg = Some((msg, Instant::now()));
    }

    fn is_ancestor(&self, candidate: usize, target: usize) -> bool {
        let mut current = self.nodes.get(target).and_then(|n| n.parent);
        while let Some(parent_id) = current {
            if parent_id == candidate {
                return true;
            }
            current = self.nodes.get(parent_id).and_then(|n| n.parent);
        }
        false
    }

    fn get_node_age_card_colors(&self, node: &Node) -> (egui::Color32, egui::Color32, egui::Color32) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let elapsed = now.saturating_sub(node.modified_timestamp);

        let red_sec = self.threshold_red_hours * 3600;
        let yellow_sec = self.threshold_yellow_hours * 3600;
        let green_sec = self.threshold_green_days * 86400;

        if self.dark_mode {
            if elapsed <= red_sec {
                (egui::Color32::from_rgb(69, 10, 10), egui::Color32::from_rgb(239, 68, 68), egui::Color32::from_rgb(254, 202, 202))
            } else if elapsed <= yellow_sec {
                (egui::Color32::from_rgb(69, 26, 3), egui::Color32::from_rgb(245, 158, 11), egui::Color32::from_rgb(253, 230, 138))
            } else if elapsed <= green_sec {
                (egui::Color32::from_rgb(6, 78, 59), egui::Color32::from_rgb(16, 185, 129), egui::Color32::from_rgb(167, 243, 208))
            } else {
                (egui::Color32::from_rgb(30, 41, 59), egui::Color32::from_rgb(100, 116, 139), egui::Color32::from_rgb(203, 213, 225))
            }
        } else {
            if elapsed <= red_sec {
                (egui::Color32::from_rgb(254, 226, 226), egui::Color32::from_rgb(239, 68, 68), egui::Color32::from_rgb(185, 28, 28))
            } else if elapsed <= yellow_sec {
                (egui::Color32::from_rgb(254, 243, 199), egui::Color32::from_rgb(245, 158, 11), egui::Color32::from_rgb(180, 83, 9))
            } else if elapsed <= green_sec {
                (egui::Color32::from_rgb(209, 250, 229), egui::Color32::from_rgb(16, 185, 129), egui::Color32::from_rgb(4, 120, 87))
            } else {
                (egui::Color32::from_rgb(241, 245, 249), egui::Color32::from_rgb(148, 163, 184), egui::Color32::from_rgb(71, 85, 105))
            }
        }
    }

    fn matches_filter(&self, node: &Node) -> bool {
        if !self.search_query.is_empty() {
            let q = self.search_query.to_lowercase();
            if !node.name.to_lowercase().contains(&q) && !node.hash_hex.to_lowercase().contains(&q) {
                return false;
            }
        }

        if !self.filter_extension.is_empty() && !node.is_dir {
            let ext = self.filter_extension.trim_start_matches('.').to_lowercase();
            let file_ext = node
                .path
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase();
            if file_ext != ext {
                return false;
            }
        }

        if !node.is_dir {
            let size_mb = node.size_bytes as f32 / (1024.0_f32 * 1024.0_f32);
            if size_mb > self.filter_max_size_mb {
                return false;
            }
        }

        true
    }

    fn export_current_json(&mut self) {
        if let Some(ref audit) = self.last_audit {
            let report = audit.to_exported_report(&self.nodes);
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("merkle_audit_report.json")
                .add_filter("JSON Report", &["json"])
                .save_file()
            {
                match save_report_to_json(&report, &path) {
                    Ok(_) => self.set_notification(format!("✅ Reporte exportado a {}", path.display())),
                    Err(e) => self.set_notification(format!("❌ Error exportando JSON: {}", e)),
                }
            }
        } else {
            self.set_notification("⚠️ No hay auditoría activa para exportar".to_string());
        }
    }

    // --- SAFETY GUARANTEE: RELOCATE / MOVE FILE (NO DELETIONS EVER) ---
    pub fn move_node_to_folder(&mut self, src_node_id: usize, dest_folder_id: usize) {
        if src_node_id == dest_folder_id {
            return;
        }

        let (src_path, dest_dir) = match (self.nodes.get(src_node_id), self.nodes.get(dest_folder_id)) {
            (Some(src), Some(dest)) if dest.is_dir => (src.path.clone(), dest.path.clone()),
            _ => return,
        };

        if let Some(file_name) = src_path.file_name() {
            let target_path = dest_dir.join(file_name);
            if target_path.exists() {
                self.set_notification("⚠️ Ya existe un archivo con ese nombre en la carpeta destino".to_string());
                return;
            }

            // Perform relocation move (rename). Absolute rule: NO DELETION CALLS EVER.
            match fs::rename(&src_path, &target_path) {
                Ok(_) => {
                    self.push_undo_snapshot(&format!("Mover {} a {}", file_name.to_string_lossy(), dest_dir.to_string_lossy()));
                    self.set_notification(format!("📦 Movido {} a {}", file_name.to_string_lossy(), dest_dir.to_string_lossy()));
                    self.reload_directory_background();
                }
                Err(e) => {
                    self.set_notification(format!("❌ Error moviendo archivo: {}", e));
                }
            }
        }
    }

    fn configure_custom_styles(&self, ctx: &egui::Context) {
        let mut visuals = if self.dark_mode {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };

        if self.dark_mode {
            // High-End Translucent Dark Glassmorphism
            visuals.window_fill = egui::Color32::from_rgba_unmultiplied(15, 23, 42, 215);
            visuals.panel_fill = egui::Color32::from_rgba_unmultiplied(18, 26, 45, 205);
            visuals.extreme_bg_color = egui::Color32::from_rgba_unmultiplied(12, 18, 32, 220);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgba_unmultiplied(26, 36, 60, 190);
            visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(255, 255, 255, 40));
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgba_unmultiplied(30, 42, 68, 195);
            visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(255, 255, 255, 35));
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgba_unmultiplied(45, 62, 98, 220);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgba_unmultiplied(37, 99, 235, 230);
            visuals.widgets.inactive.rounding = egui::Rounding::same(16.0_f32);
            visuals.widgets.hovered.rounding = egui::Rounding::same(16.0_f32);
            visuals.widgets.active.rounding = egui::Rounding::same(16.0_f32);
            visuals.window_rounding = egui::Rounding::same(18.0_f32);
            visuals.menu_rounding = egui::Rounding::same(16.0_f32);
        } else {
            // High-End Translucent Titanium White Glassmorphism (Matching prompt & reference image)
            visuals.window_fill = egui::Color32::from_rgba_unmultiplied(255, 255, 255, 215);
            visuals.panel_fill = egui::Color32::from_rgba_unmultiplied(252, 253, 255, 205);
            visuals.extreme_bg_color = egui::Color32::from_rgba_unmultiplied(241, 245, 249, 215);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgba_unmultiplied(255, 255, 255, 220);
            visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(255, 255, 255, 230));
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgba_unmultiplied(241, 245, 249, 210);
            visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(255, 255, 255, 240));
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgba_unmultiplied(226, 232, 240, 230);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgba_unmultiplied(203, 213, 225, 240);
            visuals.widgets.inactive.rounding = egui::Rounding::same(16.0_f32);
            visuals.widgets.hovered.rounding = egui::Rounding::same(16.0_f32);
            visuals.widgets.active.rounding = egui::Rounding::same(16.0_f32);
            visuals.window_rounding = egui::Rounding::same(18.0_f32);
            visuals.menu_rounding = egui::Rounding::same(16.0_f32);
        }

        ctx.set_visuals(visuals);
    }

    fn render_glassmorphic_background(painter: &egui::Painter, rect: egui::Rect, dark_mode: bool, time: f32) {
        // 1. Soft Studio Gradient Fill (titanium white / light grey studio)
        let bg_color = if dark_mode {
            egui::Color32::from_rgb(13, 18, 29)
        } else {
            egui::Color32::from_rgb(244, 245, 248)
        };

        // Draw studio background rectangle
        painter.rect_filled(rect, 0.0, bg_color);

        // 2. Weightless floating 3D translucent crystal spheres & bokeh geometry (Antigravity aesthetic)
        let sphere_positions = [
            (0.18, 0.25, 75.0, 0.35),
            (0.82, 0.20, 105.0, 0.22),
            (0.12, 0.75, 120.0, 0.15),
            (0.88, 0.70, 85.0, 0.30),
            (0.48, 0.15, 50.0, 0.45),
            (0.55, 0.85, 90.0, 0.18),
            (0.35, 0.60, 40.0, 0.55),
        ];

        for (idx, (xr, yr, r, speed)) in sphere_positions.iter().enumerate() {
            let float_y = (time * speed + idx as f32 * 1.5).sin() * 14.0;
            let float_x = (time * speed * 0.7 + idx as f32 * 2.1).cos() * 10.0;

            let cx = rect.min.x + rect.width() * xr + float_x;
            let cy = rect.min.y + rect.height() * yr + float_y;
            let center = egui::pos2(cx, cy);

            let fill_alpha = if dark_mode { 12 } else { 25 };
            let stroke_alpha = if dark_mode { 30 } else { 55 };

            // Translucent glass body fill
            painter.circle_filled(
                center,
                *r,
                if dark_mode {
                    egui::Color32::from_white_alpha(fill_alpha)
                } else {
                    egui::Color32::from_rgba_unmultiplied(255, 255, 255, fill_alpha)
                },
            );

            // Soft glass edge stroke (bokeh rim highlight)
            painter.circle_stroke(
                center,
                *r,
                egui::Stroke::new(
                    1.5_f32,
                    if dark_mode {
                        egui::Color32::from_white_alpha(stroke_alpha)
                    } else {
                        egui::Color32::from_rgba_unmultiplied(255, 255, 255, stroke_alpha)
                    },
                ),
            );

            // Inner specular reflection highlight dot
            let highlight_pos = center - egui::vec2(r * 0.35, r * 0.35);
            painter.circle_filled(
                highlight_pos,
                r * 0.18,
                if dark_mode {
                    egui::Color32::from_white_alpha(40)
                } else {
                    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 95)
                },
            );
        }
    }
}

pub fn get_extension_card_colors(node: &Node, dark_mode: bool) -> (egui::Color32, egui::Color32, egui::Color32) {
    if node.is_dir {
        if dark_mode {
            return (
                egui::Color32::from_rgb(45, 32, 10),    // Dark Warm Amber Fill
                egui::Color32::from_rgb(245, 158, 11),  // Amber Border
                egui::Color32::from_rgb(254, 243, 199), // Amber Text
            );
        } else {
            return (
                egui::Color32::from_rgb(254, 243, 199), // Soft Warm Amber Fill
                egui::Color32::from_rgb(217, 119, 6),   // Solid Amber Border
                egui::Color32::from_rgb(120, 53, 15),  // Dark Text
            );
        }
    }

    let ext = node
        .path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    match ext.as_str() {
        "pdf" => {
            if dark_mode {
                (egui::Color32::from_rgb(60, 20, 20), egui::Color32::from_rgb(239, 68, 68), egui::Color32::WHITE)
            } else {
                (egui::Color32::from_rgb(254, 226, 226), egui::Color32::from_rgb(220, 38, 38), egui::Color32::from_rgb(153, 27, 27))
            }
        }
        "rs" | "py" | "js" | "ts" | "json" | "html" | "css" | "toml" | "yaml" | "xml" | "cpp" | "c" => {
            if dark_mode {
                (egui::Color32::from_rgb(15, 45, 30), egui::Color32::from_rgb(16, 185, 129), egui::Color32::WHITE)
            } else {
                (egui::Color32::from_rgb(209, 250, 229), egui::Color32::from_rgb(5, 150, 105), egui::Color32::from_rgb(6, 78, 59))
            }
        }
        "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "bmp" => {
            if dark_mode {
                (egui::Color32::from_rgb(15, 35, 60), egui::Color32::from_rgb(14, 165, 233), egui::Color32::WHITE)
            } else {
                (egui::Color32::from_rgb(224, 242, 254), egui::Color32::from_rgb(2, 132, 199), egui::Color32::from_rgb(12, 74, 110))
            }
        }
        "mp3" | "wav" | "flac" | "ogg" | "mp4" | "mkv" | "avi" | "mov" | "webm" => {
            if dark_mode {
                (egui::Color32::from_rgb(50, 15, 45), egui::Color32::from_rgb(236, 72, 153), egui::Color32::WHITE)
            } else {
                (egui::Color32::from_rgb(252, 231, 243), egui::Color32::from_rgb(219, 39, 119), egui::Color32::from_rgb(131, 24, 67))
            }
        }
        "rfa" | "rvt" | "dwg" | "dxf" => {
            if dark_mode {
                (egui::Color32::from_rgb(25, 25, 60), egui::Color32::from_rgb(99, 102, 241), egui::Color32::WHITE)
            } else {
                (egui::Color32::from_rgb(224, 231, 255), egui::Color32::from_rgb(79, 70, 229), egui::Color32::from_rgb(49, 46, 129))
            }
        }
        "zip" | "rar" | "7z" | "tar" | "gz" => {
            if dark_mode {
                (egui::Color32::from_rgb(55, 30, 15), egui::Color32::from_rgb(249, 115, 22), egui::Color32::WHITE)
            } else {
                (egui::Color32::from_rgb(255, 237, 213), egui::Color32::from_rgb(234, 88, 12), egui::Color32::from_rgb(154, 52, 18))
            }
        }
        _ => {
            let mut hash: u32 = 5381;
            for b in ext.bytes() {
                hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u32);
            }
            let hue = (hash % 360) as f32 / 360.0_f32;
            let fill = egui::epaint::Hsva::new(hue, if dark_mode { 0.45 } else { 0.20 }, if dark_mode { 0.25 } else { 0.95 }, 1.0);
            let border = egui::epaint::Hsva::new(hue, 0.75, if dark_mode { 0.85 } else { 0.60 }, 1.0);
            let text = if dark_mode { egui::Color32::WHITE } else { egui::Color32::from_rgb(15, 23, 42) };
            (fill.into(), border.into(), text)
        }
    }
}

pub fn get_file_icon(node: &Node) -> &'static str {
    if node.is_dir {
        return "📁";
    }
    let ext = node
        .path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    match ext.as_str() {
        "pdf" => "📕",
        "doc" | "docx" | "txt" | "md" | "log" | "rtf" => "📝",
        "rs" | "js" | "ts" | "py" | "json" | "html" | "css" | "toml" | "yaml" | "xml" | "cpp" | "c" => "💻",
        "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "bmp" => "🖼️",
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" => "📦",
        "mp3" | "wav" | "flac" | "ogg" => "🎵",
        "mp4" | "mkv" | "avi" | "mov" | "webm" => "🎬",
        "exe" | "bat" | "cmd" | "sh" | "msi" => "⚙️",
        _ => "📄",
    }
}

// --- COMPACT 5-COLUMN GRID & NON-OVERLAPPING HIERARCHICAL LAYOUT ---
fn compute_subtree_bounds(
    nodes: &[Node],
    node_id: usize,
    visible_set: &HashSet<usize>,
) -> f32 {
    let node = match nodes.get(node_id) {
        Some(n) => n,
        None => return 210.0_f32,
    };

    let vis_children: Vec<usize> = node
        .children
        .iter()
        .copied()
        .filter(|id| visible_set.contains(id))
        .collect();

    if vis_children.is_empty() {
        return 210.0_f32;
    }

    if vis_children.len() > 8 {
        // Compact 5-column grid composition for folders with > 8 items
        let cols = 5;
        let spacing_x = 195.0_f32;
        let num_cols = vis_children.len().min(cols);
        (num_cols as f32 * spacing_x).max(210.0_f32)
    } else {
        let mut total_width = 0.0_f32;
        for &child_id in &vis_children {
            total_width += compute_subtree_bounds(nodes, child_id, visible_set);
        }
        total_width.max(210.0_f32)
    }
}

fn place_subtrees_non_overlapping(
    nodes: &[Node],
    node_id: usize,
    visible_set: &HashSet<usize>,
    left_x: f32,
    depth: usize,
    top_y: f32,
    positions: &mut HashMap<usize, egui::Pos2>,
) -> f32 {
    let node = match nodes.get(node_id) {
        Some(n) => n,
        None => return left_x + 210.0_f32,
    };

    let vis_children: Vec<usize> = node
        .children
        .iter()
        .copied()
        .filter(|id| visible_set.contains(id))
        .collect();

    let level_y = top_y + (depth as f32 * 110.0_f32);

    if vis_children.is_empty() {
        let center_x = left_x + 105.0_f32;
        positions.insert(node_id, egui::pos2(center_x, level_y));
        return left_x + 210.0_f32;
    }

    if vis_children.len() > 8 {
        // Render as a clean, compact 5-column Grid Composition
        let cols = 5;
        let spacing_x = 195.0_f32;
        let spacing_y = 65.0_f32;
        let grid_cols = vis_children.len().min(cols);
        let grid_width = grid_cols as f32 * spacing_x;
        let center_x = left_x + (grid_width / 2.0_f32);

        positions.insert(node_id, egui::pos2(center_x, level_y));

        let start_x = left_x + (spacing_x / 2.0_f32);
        let start_y = level_y + 110.0_f32;

        for (i, &child_id) in vis_children.iter().enumerate() {
            let col = i % cols;
            let row = i / cols;
            let child_x = start_x + (col as f32 * spacing_x);
            let child_y = start_y + (row as f32 * spacing_y);

            positions.insert(child_id, egui::pos2(child_x, child_y));
        }

        left_x + grid_width.max(210.0_f32)
    } else {
        let mut current_x = left_x;
        for &child_id in &vis_children {
            current_x = place_subtrees_non_overlapping(
                nodes,
                child_id,
                visible_set,
                current_x,
                depth + 1,
                top_y,
                positions,
            );
        }

        let subtree_width = current_x - left_x;
        let center_x = left_x + (subtree_width / 2.0_f32);
        positions.insert(node_id, egui::pos2(center_x, level_y));

        current_x.max(left_x + 210.0_f32)
    }
}

impl eframe::App for MerkleApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.configure_custom_styles(ctx);

        // Global Keyboard Shortcuts (Ctrl+Z for Undo, Ctrl+Y for Redo)
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::Z)) {
            self.undo();
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::Y)) {
            self.redo();
        }

        // Receive Worker Messages
        if let Ok(msg) = self.rx.try_recv() {
            match msg {
                WorkerMessage::TreeBuilt {
                    nodes,
                    audit_record,
                    ..
                } => {
                    let was_empty = self.nodes.is_empty();
                    self.nodes = nodes;
                    self.last_audit = Some(audit_record);
                    self.is_loading = false;
                    self.history_log_lines = Self::load_history_log();

                    // Only reset camera position on initial load of an empty workspace
                    if was_empty {
                        self.focused_root_id = None;
                        self.zoom_scale = 1.0_f32;
                        self.pan_offset = egui::Vec2::ZERO;
                        self.custom_node_positions.clear();
                        self.set_notification("✅ Árbol de Merkle cargado y centrado".to_string());
                    } else {
                        self.set_notification("🔄 Árbol actualizado en segundo plano (Sin interrupción)".to_string());
                    }
                }
                WorkerMessage::Progress { current, total } => {
                    self.progress = (current, total);
                }
                WorkerMessage::FileAdded(msg) => {
                    self.set_notification(msg);
                }
                WorkerMessage::Error(e) => {
                    self.is_loading = false;
                    self.set_notification(format!("❌ Error: {}", e));
                }
            }
        }

        // Receive Watcher Messages with Debounce
        if let Ok(msg) = self.watcher_rx.try_recv() {
            match msg {
                WatcherMessage::FileChanged(_path, desc) => {
                    play_alert_sound("Resources/alert.wav");
                    self.set_notification(format!("🔔 Cambio en tiempo real: {}", desc));
                    // Queue debounced background reload 500ms in the future
                    self.pending_watcher_reload = Some(Instant::now() + Duration::from_millis(500));
                }
                WatcherMessage::Error(e) => {
                    self.set_notification(format!("⚠️ Watcher Error: {}", e));
                }
            }
        }

        // Execute debounced watcher reload without interrupting UI
        if let Some(reload_at) = self.pending_watcher_reload {
            if Instant::now() >= reload_at {
                self.pending_watcher_reload = None;
                self.reload_directory_background();
            }
        }

        // --- TOP PANEL / HEADER ---
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(16.0_f32, 14.0_f32)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // Logo & App Name
                    ui.label(
                        egui::RichText::new("🛡 Merkle Audit Explorer")
                            .font(egui::FontId::proportional(18.0_f32))
                            .strong()
                            .color(if self.dark_mode { egui::Color32::WHITE } else { egui::Color32::from_rgb(15, 23, 42) }),
                    );

                    ui.add_space(14.0_f32);

                    // Navigation Tabs (Strictly 3 Tabs: Visual Explorer, Traceability, Settings)
                    ui.horizontal(|ui| {
                        ui.style_mut().spacing.button_padding = egui::vec2(14.0_f32, 7.0_f32);
                        if ui
                            .selectable_label(self.active_tab == AppTab::Explorer, "🌳 Explorador Visual")
                            .clicked()
                        {
                            self.active_tab = AppTab::Explorer;
                        }
                        if ui
                            .selectable_label(self.active_tab == AppTab::Traceability, "📜 Trazabilidad y Reportes")
                            .clicked()
                        {
                            self.active_tab = AppTab::Traceability;
                        }
                        if ui
                            .selectable_label(self.active_tab == AppTab::Settings, "⚙ Ajustes")
                            .clicked()
                        {
                            self.active_tab = AppTab::Settings;
                        }
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Dark/Light Mode Toggle
                        let theme_btn = if self.dark_mode { "☀ Light" } else { "🌙 Dark" };
                        if ui.button(theme_btn).clicked() {
                            self.dark_mode = !self.dark_mode;
                        }

                        // Algorithm selector
                        egui::ComboBox::from_id_source("alg_select")
                            .selected_text(format!("Hash: {}", self.hash_algorithm))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.hash_algorithm, HashAlgorithm::Sha256, "SHA-256");
                                ui.selectable_value(&mut self.hash_algorithm, HashAlgorithm::Blake3, "BLAKE3");
                            });
                    });
                });

                ui.add_space(8.0_f32);
                ui.separator();
                ui.add_space(6.0_f32);

                // Context-Sensitive Action Bar
                match self.active_tab {
                    AppTab::Explorer => {
                        egui::ScrollArea::horizontal()
                            .id_source("explorer_toolbar_scroll")
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if ui.button("📁 Seleccionar Carpeta").clicked() {
                                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                            self.load_directory(path);
                                        }
                                    }

                                    if self.watcher_active {
                                        if ui.button("⏹ Detener Monitoreo").clicked() {
                                            self.stop_watcher();
                                        }
                                    } else if let Some(ref path) = self.current_path.clone() {
                                        if ui.button("👁 Monitorear Cambios").clicked() {
                                            self.start_watcher(path.clone());
                                        }
                                    }

                                    ui.separator();

                                    if self.focused_root_id.is_some() {
                                        if ui.button("🏠 Raíz Principal").clicked() {
                                            self.push_undo_snapshot("Volver a raíz principal");
                                            self.focused_root_id = None;
                                        }
                                    }

                                    ui.label("🔍");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.search_query)
                                            .hint_text("Buscar por nombre o hash...")
                                            .desired_width(170.0_f32),
                                    );

                                    ui.label("Tipo:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.filter_extension)
                                            .hint_text("ej. pdf, rs")
                                            .desired_width(55.0_f32),
                                    );

                                    ui.separator();
                                    ui.label("Modo Color:");
                                    ui.selectable_value(&mut self.color_mode, NodeColorMode::ByExtension, "🎨 Extensión");
                                    ui.selectable_value(&mut self.color_mode, NodeColorMode::ByAge, "⏳ Antigüedad");

                                    if ui.button("🎯 Reset Cam").clicked() {
                                        self.push_undo_snapshot("Reset Cámara");
                                        self.zoom_scale = 1.0_f32;
                                        self.pan_offset = egui::Vec2::ZERO;
                                        self.custom_node_positions.clear();
                                        self.set_notification("🎯 Cámara y posiciones reubicadas".to_string());
                                    }

                                    ui.separator();

                                    ui.label("⚡ Vel. Desplazamiento:");
                                    ui.add_sized([75.0, 20.0], egui::Slider::new(&mut self.pan_speed_mult, 0.5_f32..=6.0_f32).text("x"));

                                    ui.label("🔍 Vel. Zoom:");
                                    ui.add_sized([85.0, 20.0], egui::Slider::new(&mut self.zoom_speed_factor, 1.01_f32..=1.12_f32));
                                });
                            });
                    }
                    AppTab::Traceability => {
                        ui.horizontal(|ui| {
                            if ui.button("📥 Exportar Reporte JSON").clicked() {
                                self.export_current_json();
                            }

                            ui.separator();

                            if ui.add_enabled(!self.undo_stack.is_empty(), egui::Button::new("↩ Deshacer")).clicked() {
                                self.undo();
                            }
                            if ui.add_enabled(!self.redo_stack.is_empty(), egui::Button::new("↪ Rehacer")).clicked() {
                                self.redo();
                            }
                        });
                    }
                    AppTab::Settings => {
                        ui.horizontal(|ui| {
                            ui.label("⚙️ Preferencias y Umbrales de Sistema");
                        });
                    }
                }

                    if self.is_loading {
                        ui.spinner();
                        if self.progress.1 > 0 {
                            ui.label(format!("Procesando {}/{} archivos...", self.progress.0, self.progress.1));
                        } else {
                            ui.label("Escaneando...");
                        }
                    }

                // Status Audit Record Bar
                if let Some(ref audit) = self.last_audit {
                    ui.add_space(4.0_f32);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("MERKLE ROOT ({}):", audit.algorithm))
                                .small()
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new(&audit.root_hash)
                                .small()
                                .monospace()
                                .color(egui::Color32::from_rgb(16, 185, 129)),
                        );
                        ui.separator();
                        ui.label(
                            egui::RichText::new(format!("Ruta: {}", audit.target_path))
                                .small()
                                .color(egui::Color32::GRAY),
                        );
                    });
                }
            });

        // --- BOTTOM BAR / LEGEND & TOAST ---
        egui::TopBottomPanel::bottom("legend")
            .frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(16.0_f32, 8.0_f32)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Antigüedad:").small());
                    ui.colored_label(
                        self.color_red,
                        format!("■ <{}h (Reciente)", self.threshold_red_hours),
                    );
                    ui.colored_label(
                        self.color_yellow,
                        format!("■ <{}h (Medio)", self.threshold_yellow_hours),
                    );
                    ui.colored_label(
                        self.color_green,
                        format!("■ <{}d (Estable)", self.threshold_green_days),
                    );
                    ui.colored_label(self.color_old, "■ Antiguo");

                    ui.separator();
                    ui.label(format!("Nodos Totales: {}", self.nodes.len()));

                    if self.forensic_mode {
                        let open_count = self.open_files_cache.values().filter(|&&v| v).count();
                        if open_count > 0 {
                            ui.separator();
                            ui.colored_label(
                                egui::Color32::from_rgb(239, 68, 68),
                                format!("🔥 {} Archivos en uso por procesos", open_count),
                            );
                        }
                    }

                    if let Some((ref msg, time)) = self.notification_msg.clone() {
                        if time.elapsed() < Duration::from_secs(6) {
                            ui.label(
                                egui::RichText::new(msg)
                                    .color(egui::Color32::from_rgb(37, 99, 235))
                                    .strong(),
                            );
                        }
                    }

                    // Persistent Developer Watermark Credit Note (Mandatory License)
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new("⚡ Desarrollado por Guillermo Jhoel Hernández Gómez | Licencia Merkle Audit Explorer")
                                .small()
                                .color(if self.dark_mode { egui::Color32::from_gray(140) } else { egui::Color32::from_gray(100) }),
                        );
                    });
                });
            });

        // --- RIGHT PANEL (NODE DETAILS & FILE PREVIEW SPLIT) ---
        if self.active_tab == AppTab::Explorer {
            if let Some(sel_id) = self.selected_node_id {
                if let Some(node) = self.nodes.get(sel_id).cloned() {
                    let mut close_panel = false;
                    egui::SidePanel::right("node_details")
                        .resizable(true)
                        .default_width(330.0_f32)
                        .show(ctx, |ui| {
                            ui.add_space(8.0_f32);
                            ui.horizontal(|ui| {
                                ui.heading(format!("{} Detalles del Nodo", get_file_icon(&node)));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(egui::RichText::new("❌").strong()).clicked() {
                                        close_panel = true;
                                    }
                                });
                            });
                            ui.separator();
                            ui.add_space(8.0_f32);

                            ui.label(egui::RichText::new("Nombre:").strong());
                            ui.label(&node.name);

                            ui.add_space(6.0_f32);
                            ui.label(egui::RichText::new("Tipo:").strong());
                            ui.label(if node.is_dir { "📁 Directorio (Contenedor)" } else { "📄 Archivo (Hoja)" });

                            ui.add_space(6.0_f32);
                            ui.label(egui::RichText::new("Ruta Completa:").strong());
                            ui.label(node.path.to_string_lossy().to_string());

                            ui.add_space(6.0_f32);
                            ui.label(egui::RichText::new("Hash Integrity:").strong());
                            ui.label(
                                egui::RichText::new(&node.hash_hex)
                                    .monospace()
                                    .small()
                                    .color(egui::Color32::from_rgb(16, 185, 129)),
                            );

                            ui.add_space(6.0_f32);
                            ui.label(egui::RichText::new("Tamaño:").strong());
                            ui.label(format!("{:.2} KB ({} bytes)", node.size_bytes as f32 / 1024.0_f32, node.size_bytes));

                            ui.add_space(10.0_f32);

                            if node.is_dir {
                                if ui.button("🔍 Enfocar Subcarpeta como Raíz Visual").clicked() {
                                    self.push_undo_snapshot("Enfocar subcarpeta");
                                    self.focused_root_id = Some(node.id);
                                    self.zoom_scale = 1.0_f32;
                                    self.pan_offset = egui::Vec2::ZERO;
                                }
                            }

                            ui.add_space(8.0_f32);
                            if ui.button("🚀 Abrir en Sistema").clicked() {
                                let _ = open::that(&node.path);
                            }

                            ui.add_space(12.0_f32);
                            if ui.button("❌ Cerrar Panel").clicked() {
                                close_panel = true;
                            }
                        });

                    if close_panel {
                        self.selected_node_id = None;
                    }
                }
            }
        }

        // --- MAIN CENTRAL PANEL AREA ---
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                AppTab::Explorer => self.render_explorer_tab(ui, ctx),
                AppTab::Traceability => self.render_traceability_tab(ui),
                AppTab::Settings => self.render_settings_tab(ui),
            }
        });

        // Render Pending File Move Confirmation Dialog Window
        self.render_move_confirmation_dialog(ctx);

        // Request repaint for animated particles along Merkle tree connections
        ctx.request_repaint_after(Duration::from_millis(33));
    }
}

impl MerkleApp {
    fn render_move_confirmation_dialog(&mut self, ctx: &egui::Context) {
        let (src_id, dest_id) = match self.pending_move_confirmation {
            Some(pair) => pair,
            None => return,
        };

        let src_node = self.nodes.get(src_id).cloned();
        let dest_node = self.nodes.get(dest_id).cloned();

        let (src_name, src_icon) = match src_node {
            Some(ref n) => (n.name.clone(), get_file_icon(n)),
            None => ("Archivo".to_string(), "📄"),
        };

        let (dest_name, dest_path) = match dest_node {
            Some(ref n) => (n.name.clone(), n.path.clone()),
            None => ("Carpeta Destino".to_string(), PathBuf::new()),
        };

        let mut confirm_action = false;
        let mut cancel_action = false;

        egui::Window::new("📦 Confirmar Traslado de Archivo")
            .collapsible(false)
            .resizable(false)
            .pivot(egui::Align2::CENTER_CENTER)
            .fixed_pos(ctx.screen_rect().center())
            .show(ctx, |ui| {
                ui.set_max_width(420.0);

                ui.vertical_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("📦 Reubicación de Archivo en Disco").strong().size(16.0));
                    ui.add_space(4.0);
                });

                ui.separator();
                ui.add_space(8.0);

                ui.label("¿Estás seguro de que deseas mover este elemento a la carpeta seleccionada?");
                ui.add_space(10.0);

                egui::Frame::group(ui.style())
                    .fill(if self.dark_mode { egui::Color32::from_rgb(15, 23, 42) } else { egui::Color32::from_rgb(241, 245, 249) })
                    .rounding(8.0)
                    .inner_margin(egui::Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Elemento Origen:");
                            ui.label(egui::RichText::new(format!("{} {}", src_icon, src_name)).strong());
                        });
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label("Carpeta Destino:");
                            ui.label(egui::RichText::new(format!("📁 {}", dest_name)).strong().color(egui::Color32::from_rgb(245, 158, 11)));
                        });
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new(format!("Ruta destino: {}", dest_path.join(&src_name).display())).small().color(egui::Color32::GRAY));
                    });

                ui.add_space(10.0);
                ui.label(egui::RichText::new("⚠️ El archivo será cambiado de directorio. El árbol Merkle se actualizará de inmediato.").small().italics());

                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if ui.add_sized([180.0, 32.0], egui::Button::new(egui::RichText::new("✅ Confirmar y Mover").strong()).fill(egui::Color32::from_rgb(37, 99, 235))).clicked() {
                        confirm_action = true;
                    }

                    ui.add_space(12.0);

                    if ui.add_sized([130.0, 32.0], egui::Button::new("❌ Cancelar")).clicked() {
                        cancel_action = true;
                    }
                });
            });

        if confirm_action {
            self.pending_move_confirmation = None;
            self.move_node_to_folder(src_id, dest_id);
        } else if cancel_action {
            self.pending_move_confirmation = None;
            self.set_notification("ℹ️ Traslado de archivo cancelado".to_string());
        }

        // --- STARTUP WELCOME MODAL OVERLAY ---
        if self.show_welcome_dialog {
            let screen_rect = ctx.screen_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("welcome_overlay_layer")));
            painter.rect_filled(
                screen_rect,
                0.0,
                egui::Color32::from_black_alpha(135),
            );

            egui::Window::new("¡Bienvenido/a!")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .fixed_size(egui::vec2(450.0, 490.0))
                .frame(
                    egui::Frame::window(&ctx.style())
                        .fill(if self.dark_mode {
                            egui::Color32::from_rgb(18, 26, 45)
                        } else {
                            egui::Color32::WHITE
                        })
                        .rounding(20.0)
                        .inner_margin(egui::Margin::same(24.0))
                        .stroke(egui::Stroke::new(1.5_f32, egui::Color32::from_rgb(37, 99, 235))),
                )
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        // Avatar image maintaining aspect ratio
                        ui.add(
                            egui::Image::new(egui::include_image!("../Resources/estatico.png"))
                                .max_height(140.0_f32)
                                .fit_to_exact_size(egui::vec2(105.0, 140.0))
                                .rounding(12.0),
                        );

                        ui.add_space(14.0_f32);

                        ui.label(
                            egui::RichText::new("¡Bienvenido/a a una nueva forma de explorar tus datos!")
                                .font(egui::FontId::proportional(16.5_f32))
                                .strong()
                                .color(if self.dark_mode { egui::Color32::WHITE } else { egui::Color32::from_rgb(15, 23, 42) }),
                        );

                        ui.add_space(8.0_f32);

                        ui.label(
                            egui::RichText::new("Diseñado y desarrollado por Guillermo Jhoel HG.")
                                .font(egui::FontId::proportional(13.0_f32))
                                .italics()
                                .color(egui::Color32::from_rgb(37, 99, 235)),
                        );

                        ui.add_space(12.0_f32);

                        ui.label(
                            egui::RichText::new(
                                "Esta herramienta fue creada para darte velocidad, trazabilidad y control visual total sobre tus archivos. Si te es de utilidad en tu día a día, ¡te agradecería enormemente que la compartas!"
                            )
                            .font(egui::FontId::proportional(13.5_f32))
                            .color(if self.dark_mode { egui::Color32::from_rgb(203, 213, 225) } else { egui::Color32::from_rgb(71, 85, 105) }),
                        );

                        ui.add_space(20.0_f32);

                        if ui
                            .add_sized(
                                [240.0, 42.0],
                                egui::Button::new(
                                    egui::RichText::new("🚀 Entendido y Comenzar")
                                        .font(egui::FontId::proportional(15.0_f32))
                                        .strong()
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(37, 99, 235))
                                .rounding(21.0),
                            )
                            .clicked()
                        {
                            self.show_welcome_dialog = false;
                        }
                    });
                });
        }
    }

    fn render_explorer_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.nodes.is_empty() {
            let (response, painter) = ui.allocate_painter(ui.available_size(), egui::Sense::hover());
            Self::render_glassmorphic_background(&painter, response.rect, self.dark_mode, ctx.input(|i| i.time) as f32);

            ui.allocate_ui_at_rect(response.rect, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("🛡 Merkle Audit Explorer")
                                .font(egui::FontId::proportional(28.0_f32))
                                .strong()
                                .color(if self.dark_mode { egui::Color32::WHITE } else { egui::Color32::from_rgb(30, 41, 59) }),
                        );
                        ui.add_space(10.0_f32);
                        ui.label(
                            egui::RichText::new("Selecciona una carpeta para construir el árbol de integridad Merkle.")
                                .font(egui::FontId::proportional(15.0_f32)),
                        );
                        ui.add_space(20.0_f32);
                        if ui
                            .add_sized(
                                [220.0, 44.0],
                                egui::Button::new(
                                    egui::RichText::new("📁 Seleccionar Carpeta")
                                        .font(egui::FontId::proportional(16.0_f32))
                                        .strong()
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(37, 99, 235))
                                .rounding(22.0),
                            )
                            .clicked()
                        {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.load_directory(path);
                            }
                        }
                    });
                });
            });
            return;
        }

        // Filter nodes if focused_root_id is set (Adaptive Subtree Root)
        let root_id = self.focused_root_id.unwrap_or(0);

        let (response, painter) = ui.allocate_painter(ui.available_size(), egui::Sense::drag());

        let canvas_center_origin = egui::pos2(response.rect.center().x, response.rect.min.y + 75.0_f32);

        if response.dragged_by(egui::PointerButton::Primary)
            || response.dragged_by(egui::PointerButton::Secondary)
            || response.dragged_by(egui::PointerButton::Middle)
        {
            // Direct 1:1 screen panning using pan_speed_mult slider
            self.pan_offset += response.drag_delta() * self.pan_speed_mult;
        }

        let scroll_delta = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll_delta != 0.0_f32 {
            let zoom_factor = if scroll_delta > 0.0_f32 {
                self.zoom_speed_factor
            } else {
                2.0_f32 - self.zoom_speed_factor
            };
            let old_zoom = self.zoom_scale;
            let new_zoom = (old_zoom * zoom_factor).clamp(0.20_f32, 4.0_f32);

            if let Some(mouse_pos) = ctx.pointer_latest_pos() {
                let world_mouse = (mouse_pos - canvas_center_origin - self.pan_offset) / old_zoom;
                self.pan_offset = mouse_pos - canvas_center_origin - (world_mouse * new_zoom);

                // SMART LEVEL-OF-DETAIL AUTOMATIC FOCUS ON DEEP ZOOM:
                if new_zoom > 1.6_f32 && scroll_delta > 0.0_f32 && self.smart_zoom_focus_enabled {
                    if let Some(subfolder_id) = self.find_subfolder_at_screen_pos(mouse_pos) {
                        if Some(subfolder_id) != self.focused_root_id {
                            self.push_undo_snapshot("Auto-focus subfolder on deep zoom");
                            self.focused_root_id = Some(subfolder_id);
                            self.zoom_scale = 1.0_f32;
                            self.pan_offset = egui::Vec2::ZERO;
                            self.set_notification("🔍 Enfocado automáticamente en subcarpeta por zoom profundo".to_string());
                        }
                    }
                }
            }

            // SMART LEVEL-OF-DETAIL AUTOMATIC STEP-OUT ON FAR ZOOM:
            if new_zoom < 0.40_f32 && scroll_delta < 0.0_f32 && self.smart_zoom_focus_enabled {
                if let Some(curr_root) = self.focused_root_id {
                    let parent = self.nodes.get(curr_root).and_then(|n| n.parent);
                    self.focused_root_id = parent;
                    self.zoom_scale = 0.85_f32;
                    self.set_notification("🏠 Perspectiva Ampliada: Retornando a carpeta superior".to_string());
                }
            }

            self.zoom_scale = new_zoom;
        }

        // Render 3D Antigravity Studio Glassmorphism Background
        Self::render_glassmorphic_background(&painter, response.rect, self.dark_mode, ctx.input(|i| i.time) as f32);

        // Draw Canvas Background Pattern (Dot Grid) for Depth & Visual Richness
        let grid_spacing = 32.0_f32 * self.zoom_scale;
        if grid_spacing > 7.0_f32 {
            let dot_color = if self.dark_mode {
                egui::Color32::from_white_alpha(18)
            } else {
                egui::Color32::from_black_alpha(15)
            };
            let start_x = response.rect.min.x + (self.pan_offset.x % grid_spacing);
            let start_y = response.rect.min.y + (self.pan_offset.y % grid_spacing);
            let mut x = start_x;
            while x < response.rect.max.x {
                let mut y = start_y;
                while y < response.rect.max.y {
                    painter.circle_filled(egui::pos2(x, y), 1.2_f32 * self.zoom_scale, dot_color);
                    y += grid_spacing;
                }
                x += grid_spacing;
            }
        }

        let zoom_scale = self.zoom_scale;
        let pan_offset = self.pan_offset;
        let transform_pos = move |world_pos: egui::Pos2| -> egui::Pos2 {
            let delta = world_pos - canvas_center_origin;
            canvas_center_origin + (delta * zoom_scale) + pan_offset
        };

        // Determine visible node IDs starting from root_id
        let mut visible_node_ids = Vec::new();
        let mut queue = vec![root_id];
        while let Some(curr) = queue.pop() {
            visible_node_ids.push(curr);
            if let Some(node) = self.nodes.get(curr) {
                // PLAN ZOOM: If folder has > 4 children, collapse into sub-tree root unless focused or zoomed in!
                if node.children.len() > 4 && curr != root_id && self.zoom_scale < 1.1_f32 {
                    continue;
                }
                for &child_id in &node.children {
                    queue.push(child_id);
                }
            }
        }

        let visible_set: HashSet<usize> = visible_node_ids.iter().copied().collect();

        // Floating Focused Subtree Breadcrumbs Bar Overlay
        if let Some(focused_id) = self.focused_root_id {
            let folder_name = self.nodes.get(focused_id).map(|n| n.name.as_str()).unwrap_or("Carpeta");
            ui.allocate_ui_at_rect(
                egui::Rect::from_min_size(response.rect.min + egui::vec2(16.0, 16.0), egui::vec2(360.0, 36.0)),
                |ui| {
                    egui::Frame::none()
                        .fill(if self.dark_mode { egui::Color32::from_rgb(21, 28, 44) } else { egui::Color32::WHITE })
                        .rounding(18.0)
                        .stroke(egui::Stroke::new(1.5_f32, egui::Color32::from_rgb(139, 92, 246)))
                        .inner_margin(egui::Margin::symmetric(12.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                if ui.button("🏠 Raíz Principal").clicked() {
                                    self.focused_root_id = None;
                                    self.zoom_scale = 1.0;
                                    self.pan_offset = egui::Vec2::ZERO;
                                }
                                ui.label(egui::RichText::new("›").color(egui::Color32::GRAY));
                                ui.label(
                                    egui::RichText::new(format!("📁 {}", folder_name))
                                        .strong()
                                        .color(egui::Color32::from_rgb(132, 204, 22)),
                                );
                            });
                        });
                },
            );
        }

        // Calculate visual center for the tree at the top center of canvas (unpanned origin)
        let canvas_center_x = response.rect.center().x;
        let canvas_top_y = response.rect.min.y + 75.0_f32;

        // Perform Automatic Hierarchical Subtree & Grid Layout Placement
        let calculated_positions = compute_hierarchical_positions(
            &self.nodes,
            root_id,
            &visible_set,
            canvas_center_x,
            canvas_top_y,
        );

        // Merge calculated positions with custom dragged positions (Notion style floating drag)
        let get_final_pos = |node_id: usize, custom_pos_map: &HashMap<usize, egui::Pos2>, calc_map: &HashMap<usize, egui::Pos2>| -> Option<egui::Pos2> {
            if let Some(&custom) = custom_pos_map.get(&node_id) {
                Some(custom)
            } else {
                calc_map.get(&node_id).copied()
            }
        };

        // Draw connecting edges with animated data flow particles
        let time = ctx.input(|i| i.time) as f32;
        for &node_id in &visible_node_ids {
            if let Some(node) = self.nodes.get(node_id) {
                if let Some(&parent_id) = node.parent.as_ref() {
                    if visible_set.contains(&parent_id) {
                        if let (Some(pos_child), Some(pos_parent)) = (
                            get_final_pos(node_id, &self.custom_node_positions, &calculated_positions),
                            get_final_pos(parent_id, &self.custom_node_positions, &calculated_positions),
                        ) {
                            let screen_child = transform_pos(pos_child);
                            let screen_parent = transform_pos(pos_parent);

                            let is_active_line = match self.selected_node_id {
                                Some(sel_id) => {
                                    (sel_id == node_id || self.is_ancestor(node_id, sel_id))
                                        && (sel_id == parent_id || self.is_ancestor(parent_id, sel_id))
                                }
                                None => false,
                            };

                            let line_stroke = if is_active_line {
                                egui::Stroke::new(3.0_f32 * self.zoom_scale, egui::Color32::from_rgb(239, 68, 68))
                            } else {
                                egui::Stroke::new(
                                    1.2_f32 * self.zoom_scale,
                                    if self.dark_mode {
                                        egui::Color32::from_gray(80)
                                    } else {
                                        egui::Color32::from_rgb(203, 213, 225)
                                    },
                                )
                            };

                            painter.line_segment([screen_parent, screen_child], line_stroke);

                            // Flowing particle animation (Monochrome: Black in Light mode, White in Dark mode)
                            let speed = 0.7_f32;
                            let t = (time * speed) % 1.0_f32;
                            let particle_pos = screen_parent.lerp(screen_child, t);
                            painter.circle_filled(
                                particle_pos,
                                3.0_f32 * self.zoom_scale,
                                if self.dark_mode {
                                    egui::Color32::WHITE
                                } else {
                                    egui::Color32::from_rgb(15, 23, 42) // Crisp Black
                                },
                            );
                        }
                    }
                }
            }
        }

        let mut dragged_node_update: Option<(usize, egui::Pos2)> = None;
        let mut double_clicked_folder_id: Option<usize> = None;
        let mut move_file_request: Option<(usize, usize)> = None;
        let pointer_pos = ctx.input(|i| i.pointer.latest_pos());
        let forensic_mode_active = self.forensic_mode;

        // Detect if cursor is hovering over any destination folder card while dragging
        let mut drop_target_folder_id: Option<usize> = None;
        if let Some(cursor_p) = pointer_pos {
            for &node_id in &visible_node_ids {
                if let Some(target_node) = self.nodes.get(node_id) {
                    if target_node.is_dir {
                        if let Some(pos) = get_final_pos(node_id, &self.custom_node_positions, &calculated_positions) {
                            let screen_pos = transform_pos(pos);
                            let width = (165.0_f32 * self.zoom_scale).clamp(45.0_f32, 290.0_f32);
                            let height = (46.0_f32 * self.zoom_scale).clamp(20.0_f32, 80.0_f32);
                            let rect = egui::Rect::from_center_size(screen_pos, egui::vec2(width, height));
                            if rect.contains(cursor_p) {
                                drop_target_folder_id = Some(node_id);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let mut currently_dragging_node: Option<(Node, egui::Pos2)> = None;

        for &node_id in &visible_node_ids {
            if let Some(node) = self.nodes.get(node_id).cloned() {
                if let Some(pos) = get_final_pos(node_id, &self.custom_node_positions, &calculated_positions) {
                    let screen_pos = transform_pos(pos);

                    let is_match = self.matches_filter(&node);
                    let width = (165.0_f32 * self.zoom_scale).clamp(45.0_f32, 290.0_f32);
                    let height = (46.0_f32 * self.zoom_scale).clamp(20.0_f32, 80.0_f32);

                    let rect = egui::Rect::from_center_size(screen_pos, egui::vec2(width, height));

                    let is_selected = self.selected_node_id == Some(node.id);
                    let is_focused = self.focused_root_id == Some(node.id);
                    let is_drop_target = drop_target_folder_id == Some(node.id) && node.is_dir;
                    let is_open_by_proc = forensic_mode_active && self.open_files_cache.get(&node.id).copied().unwrap_or(false);
                    let (ext_fill, ext_border, ext_text) = match self.color_mode {
                        NodeColorMode::ByExtension => get_extension_card_colors(&node, self.dark_mode),
                        NodeColorMode::ByAge => self.get_node_age_card_colors(&node),
                    };

                    let has_active_filter = !self.search_query.is_empty() || !self.filter_extension.is_empty();

                    let (border_color, stroke_width) = if is_drop_target {
                        (egui::Color32::from_rgb(37, 99, 235), 4.5_f32) // Glowing blue destination target highlight!
                    } else if is_open_by_proc {
                        (egui::Color32::from_rgb(239, 68, 68), 3.5_f32)
                    } else if is_focused {
                        (egui::Color32::from_rgb(37, 99, 235), 3.5_f32)
                    } else if is_selected {
                        (egui::Color32::from_rgb(239, 68, 68), 3.0_f32)
                    } else if !is_match && has_active_filter {
                        (egui::Color32::TRANSPARENT, 0.0_f32) // No border line for filtered-out items
                    } else if is_match && has_active_filter {
                        (egui::Color32::from_rgb(245, 158, 11), 3.0_f32) // Amber highlight for matching items
                    } else {
                        (ext_border, 2.0_f32)
                    };

                    let fill_color = if is_drop_target {
                        egui::Color32::from_rgb(219, 234, 254) // Target folder glowing fill
                    } else if !is_match && has_active_filter {
                        ext_fill.linear_multiply(0.20_f32) // Pure low opacity without changing color tone
                    } else {
                        ext_fill
                    };

                    let node_id_persistent = ui.make_persistent_id(node.id);
                    let node_response = ui.interact(rect, node_id_persistent, egui::Sense::click_and_drag());

                    // Hand cursor (Notion style) when hovering or dragging
                    if node_response.hovered() || node_response.dragged() {
                        if node_response.dragged() {
                            ctx.set_cursor_icon(egui::CursorIcon::Grabbing);
                        } else {
                            ctx.set_cursor_icon(egui::CursorIcon::Grab);
                        }
                    }

                    // Context menu on Right Click
                    let node_name_clone = node.name.clone();
                    let node_hash_clone = node.hash_hex.clone();
                    let node_path_clone = node.path.clone();
                    let is_dir = node.is_dir;

                    node_response.context_menu(|ui| {
                        ui.label(egui::RichText::new(format!("{} {}", get_file_icon(&node), node_name_clone)).strong());
                        ui.separator();
                        ui.label("✋ Arrastra para reubicar posición o mover a carpeta");
                        if is_dir {
                            if ui.button("🔍 Enfocar como Raíz Visual").clicked() {
                                double_clicked_folder_id = Some(node.id);
                                ui.close_menu();
                            }
                        }
                        if ui.button("📋 Copiar Hash Integridad").clicked() {
                            ui.output_mut(|o| o.copied_text = node_hash_clone.clone());
                            ui.close_menu();
                        }
                        if !forensic_mode_active {
                            if ui.button("🚀 Abrir en Sistema").clicked() {
                                let _ = open::that(&node_path_clone);
                                ui.close_menu();
                            }
                        }
                    });

                    if node_response.clicked() {
                        self.selected_node_id = Some(node.id);
                    }

                    // Double click on folder focuses as visual root
                    if node_response.double_clicked() && node.is_dir {
                        double_clicked_folder_id = Some(node.id);
                    }

                    // Floating Drag & Drop (Notion Canvas Style)
                    if node_response.dragged_by(egui::PointerButton::Primary) {
                        // Only pin custom floating position if Shift is held down!
                        if ctx.input(|i| i.modifiers.shift) {
                            let delta = node_response.drag_delta() / self.zoom_scale;
                            let new_unscaled_pos = pos + delta;
                            dragged_node_update = Some((node.id, new_unscaled_pos));
                        }

                        if let Some(cursor_p) = pointer_pos {
                            currently_dragging_node = Some((node.clone(), cursor_p));
                        }
                    }

                    // Check if released over a target destination folder (drag_stopped runs on release frame)
                    if node_response.drag_stopped() || node_response.drag_stopped_by(egui::PointerButton::Primary) {
                        if let Some(target_id) = drop_target_folder_id {
                            if target_id != node.id {
                                move_file_request = Some((node.id, target_id));
                            }
                        }
                    }

                    // Render Soft Card Shadow (Notion Scrapbook Style)
                    if is_match || !has_active_filter {
                        let shadow_rect = rect.translate(egui::vec2(2.5_f32 * self.zoom_scale, 3.5_f32 * self.zoom_scale));
                        painter.rect_filled(
                            shadow_rect,
                            10.0_f32 * self.zoom_scale,
                            if self.dark_mode {
                                egui::Color32::from_black_alpha(45)
                            } else {
                                egui::Color32::from_black_alpha(25)
                            },
                        );
                    }

                    // Render Main Full-Colored Card Block Rectangle
                    painter.rect(
                        rect,
                        10.0_f32 * self.zoom_scale,
                        fill_color,
                        egui::Stroke::new(stroke_width, border_color),
                    );

                    // Top Sticker Accent Header Bar for Cards
                    if self.zoom_scale > 0.40_f32 {
                        let header_h = (8.0_f32 * self.zoom_scale).clamp(4.0_f32, 14.0_f32);
                        let header_rect = egui::Rect::from_min_size(
                            rect.min,
                            egui::vec2(rect.width(), header_h),
                        );
                        let sticker_color = if !is_match && has_active_filter {
                            ext_border.linear_multiply(0.20_f32)
                        } else {
                            ext_border
                        };
                        painter.rect_filled(
                            header_rect,
                            egui::Rounding {
                                nw: 9.0 * self.zoom_scale,
                                ne: 9.0 * self.zoom_scale,
                                sw: 0.0,
                                se: 0.0,
                            },
                            sticker_color,
                        );
                    }

                    if is_drop_target {
                        painter.text(
                            rect.center_top() - egui::vec2(0.0, 16.0),
                            egui::Align2::CENTER_CENTER,
                            "📥 Soltar para mover archivo aquí",
                            egui::FontId::proportional(12.0),
                            egui::Color32::from_rgb(37, 99, 235),
                        );
                    }

                    // PLAN ZOOM: If folder has > 4 children and isn't root, show "+N archivos" badge!
                    let has_many_children = node.is_dir && node.children.len() > 4 && node.id != root_id && self.zoom_scale < 1.1_f32;

                    // Render Icons & Text (Clean display without Hash)
                    if self.zoom_scale > 0.35_f32 {
                        let icon = get_file_icon(&node);
                        let forensic_badge = if is_open_by_proc { " 🔥" } else { "" };

                        let label_text = if has_many_children {
                            format!("{}{} {}\n📁 +{} archivos (Haz clic para explorar)", icon, forensic_badge, node.name, node.children.len())
                        } else if node.name.len() > 16 {
                            format!("{}{} {}...", icon, forensic_badge, &node.name[..13])
                        } else {
                            format!("{}{} {}", icon, forensic_badge, node.name)
                        };

                        let text_color = if is_drop_target {
                            egui::Color32::from_rgb(37, 99, 235)
                        } else if !is_match && has_active_filter {
                            ext_text.linear_multiply(0.30_f32)
                        } else {
                            ext_text
                        };

                        painter.text(
                            rect.center() + egui::vec2(0.0, 2.0_f32 * self.zoom_scale),
                            egui::Align2::CENTER_CENTER,
                            label_text,
                            egui::FontId::proportional((12.0_f32 * self.zoom_scale).clamp(8.5_f32, 19.0_f32)),
                            text_color,
                        );
                    }
                }
            }
        }

        // Render animated translucent drag ghost preview card following mouse cursor
        if let Some((dragged_node, cursor_p)) = currently_dragging_node {
            let ghost_rect = egui::Rect::from_center_size(cursor_p + egui::vec2(15.0, 15.0), egui::vec2(160.0, 42.0));
            painter.rect_filled(
                ghost_rect,
                8.0,
                egui::Color32::from_rgba_unmultiplied(37, 99, 235, 200),
            );
            painter.rect_stroke(
                ghost_rect,
                8.0_f32,
                egui::Stroke::new(2.0_f32, egui::Color32::WHITE),
            );
            painter.text(
                ghost_rect.center(),
                egui::Align2::CENTER_CENTER,
                format!("📦 Moviendo {}", dragged_node.name),
                egui::FontId::proportional(12.0),
                egui::Color32::WHITE,
            );
        }

        if let Some((src_id, dest_id)) = move_file_request {
            self.pending_move_confirmation = Some((src_id, dest_id));
        }

        if let Some((id, new_pos)) = dragged_node_update {
            self.custom_node_positions.insert(id, new_pos);
        }

        if let Some(folder_id) = double_clicked_folder_id {
            self.push_undo_snapshot("Double click focus subfolder");
            self.focused_root_id = Some(folder_id);
            self.zoom_scale = 1.0_f32;
            self.pan_offset = egui::Vec2::ZERO;
        }
    }

    fn render_traceability_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("📜 Trazabilidad, Auditoría e Historial (Snapshot Diff & Log)");
        ui.label("Herramientas de comparación de árboles Merkle, trazabilidad histórica y exportación de reportes.");
        ui.separator();
        ui.add_space(12.0_f32);

        ui.columns(2, |columns| {
            // Left Column: Snapshot Diff Comparison & JSON Export
            columns[0].vertical(|ui| {
                ui.label(egui::RichText::new("🔀 Comparación de Snapshots Diff").strong().size(15.0_f32));
                ui.add_space(8.0_f32);

                ui.horizontal(|ui| {
                    if ui.button("📄 Cargar Reporte A (Base)").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() {
                            match load_report_from_json(path) {
                                Ok(rep) => {
                                    self.diff_report_a = Some(rep);
                                    self.set_notification("✅ Reporte A cargado".to_string());
                                }
                                Err(e) => self.set_notification(format!("❌ Error: {}", e)),
                            }
                        }
                    }

                    if let Some(ref r_a) = self.diff_report_a {
                        ui.label(format!("A: {} ({})", r_a.target_path, &r_a.root_hash[..8.min(r_a.root_hash.len())]));
                    } else {
                        ui.label("Sin reporte A");
                    }
                });

                ui.add_space(6.0_f32);

                ui.horizontal(|ui| {
                    if ui.button("📄 Cargar Reporte B (Nuevo)").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() {
                            match load_report_from_json(path) {
                                Ok(rep) => {
                                    self.diff_report_b = Some(rep);
                                    self.set_notification("✅ Reporte B cargado".to_string());
                                }
                                Err(e) => self.set_notification(format!("❌ Error: {}", e)),
                            }
                        }
                    }

                    if let Some(ref r_b) = self.diff_report_b {
                        ui.label(format!("B: {} ({})", r_b.target_path, &r_b.root_hash[..8.min(r_b.root_hash.len())]));
                    } else {
                        ui.label("Sin reporte B");
                    }
                });

                ui.add_space(10.0_f32);

                if ui.button("⚡ Ejecutar Comparación Diff").clicked() {
                    match (&self.diff_report_a, &self.diff_report_b) {
                        (Some(a), Some(b)) => {
                            let res = compare_reports(a, b);
                            self.diff_result = Some(res);
                        }
                        (Some(a), None) => {
                            if let Some(ref last_audit) = self.last_audit {
                                let current_report = last_audit.to_exported_report(&self.nodes);
                                let res = compare_reports(a, &current_report);
                                self.diff_result = Some(res);
                            } else {
                                self.set_notification("⚠️ Carga un segundo reporte o abre una carpeta actual".to_string());
                            }
                        }
                        _ => {
                            self.set_notification("⚠️ Carga al menos un reporte base para comparar".to_string());
                        }
                    }
                }

                ui.add_space(12.0_f32);

                if let Some(ref diff) = self.diff_result {
                    ui.horizontal(|ui| {
                        ui.colored_label(egui::Color32::from_rgb(16, 185, 129), format!("➕ {}", diff.total_added));
                        ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("➖ {}", diff.total_removed));
                        ui.colored_label(egui::Color32::from_rgb(245, 158, 11), format!("✏️ {}", diff.total_modified));
                        ui.colored_label(egui::Color32::GRAY, format!("✓ {}", diff.total_unchanged));
                    });

                    ui.add_space(6.0_f32);
                    egui::ScrollArea::vertical().max_height(350.0_f32).show(ui, |ui| {
                        for item in &diff.items {
                            ui.horizontal(|ui| {
                                match &item.status {
                                    crate::diff::DiffStatus::Added => {
                                        ui.colored_label(egui::Color32::from_rgb(16, 185, 129), "[+]");
                                    }
                                    crate::diff::DiffStatus::Removed => {
                                        ui.colored_label(egui::Color32::from_rgb(239, 68, 68), "[-]");
                                    }
                                    crate::diff::DiffStatus::Modified { .. } => {
                                        ui.colored_label(egui::Color32::from_rgb(245, 158, 11), "[~]");
                                    }
                                    crate::diff::DiffStatus::Unchanged => {
                                        ui.colored_label(egui::Color32::GRAY, "[=]");
                                    }
                                }
                                ui.label(&item.relative_path);
                            });
                        }
                    });
                }
            });

            // Right Column: Persistent Audit Log History
            columns[1].vertical(|ui| {
                ui.label(egui::RichText::new("📜 Historial Log de Cambios (Persistente)").strong().size(15.0_f32));
                ui.add_space(8.0_f32);

                if !self.history_log_lines.is_empty() {
                    egui::ScrollArea::vertical().max_height(450.0_f32).show(ui, |ui| {
                        for line in self.history_log_lines.iter().rev() {
                            ui.label(egui::RichText::new(line).monospace().small());
                        }
                    });
                } else {
                    ui.label("No hay registros en merkle_audit_ledger.log aún.");
                }
            });
        });
    }

    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("⚙️ Ajustes de Colores y Umbrales de Antigüedad");
        ui.separator();
        ui.add_space(12.0_f32);

        ui.label(egui::RichText::new("Configuración de Umbrales de Tiempo:").strong());
        ui.add_space(8.0_f32);

        ui.horizontal(|ui| {
            ui.label("🔴 Umbral Reciente (Horas):");
            ui.add(egui::DragValue::new(&mut self.threshold_red_hours).clamp_range(1..=72));
            ui.color_edit_button_srgba(&mut self.color_red);
        });

        ui.add_space(8.0_f32);

        ui.horizontal(|ui| {
            ui.label("🟡 Umbral Medio (Horas):");
            ui.add(egui::DragValue::new(&mut self.threshold_yellow_hours).clamp_range(1..=168));
            ui.color_edit_button_srgba(&mut self.color_yellow);
        });

        ui.add_space(8.0_f32);

        ui.horizontal(|ui| {
            ui.label("🟢 Umbral Estable (Días):");
            ui.add(egui::DragValue::new(&mut self.threshold_green_days).clamp_range(1..=365));
            ui.color_edit_button_srgba(&mut self.color_green);
        });

        ui.add_space(8.0_f32);

        ui.horizontal(|ui| {
            ui.label("⚪ Archivos Antiguos:");
            ui.color_edit_button_srgba(&mut self.color_old);
        });

        ui.add_space(16.0_f32);
        ui.separator();
        ui.add_space(12.0_f32);

        ui.label(egui::RichText::new("Sensibilidad y Controles de Navegación Visual:").strong());
        ui.add_space(8.0_f32);

        ui.horizontal(|ui| {
            ui.label("⚡ Velocidad de Desplazamiento (Paneo):");
            ui.add(egui::Slider::new(&mut self.pan_speed_mult, 0.5_f32..=6.0_f32).text("x"));
        });

        ui.add_space(8.0_f32);

        ui.horizontal(|ui| {
            ui.label("🔍 Sensibilidad de Zoom de Rueda:");
            ui.add(egui::Slider::new(&mut self.zoom_speed_factor, 1.01_f32..=1.12_f32));
        });

        ui.add_space(8.0_f32);

        ui.checkbox(&mut self.smart_zoom_focus_enabled, "🧠 Auto-enfoque inteligente de subcarpetas en Zoom Profundo");

        ui.add_space(16.0_f32);
        if ui.button("🔄 Restablecer Ajustes por Defecto").clicked() {
            self.color_red = egui::Color32::from_rgb(239, 68, 68);
            self.color_yellow = egui::Color32::from_rgb(245, 158, 11);
            self.color_green = egui::Color32::from_rgb(16, 185, 129);
            self.color_old = egui::Color32::from_gray(160);
            self.pan_speed_mult = 2.0_f32;
            self.zoom_speed_factor = 1.04_f32;
            self.smart_zoom_focus_enabled = true;
            self.set_notification("🎨 Colores y navegación restablecidos".to_string());
        }
    }

    fn find_subfolder_at_screen_pos(&self, screen_pos: egui::Pos2) -> Option<usize> {
        if self.nodes.is_empty() {
            return None;
        }
        let root_id = self.focused_root_id.unwrap_or(0);

        let mut visible_node_ids = Vec::new();
        let mut queue = vec![root_id];
        while let Some(curr) = queue.pop() {
            visible_node_ids.push(curr);
            if let Some(node) = self.nodes.get(curr) {
                if node.children.len() > 4 && curr != root_id && self.zoom_scale < 1.1_f32 {
                    continue;
                }
                for &child_id in &node.children {
                    queue.push(child_id);
                }
            }
        }
        let visible_set: HashSet<usize> = visible_node_ids.iter().copied().collect();

        let calculated_positions = compute_hierarchical_positions(
            &self.nodes,
            root_id,
            &visible_set,
            0.0,
            0.0,
        );

        let transform_pos = |pos: egui::Pos2| -> egui::Pos2 {
            (pos.to_vec2() * self.zoom_scale + self.pan_offset).to_pos2()
        };

        for &node_id in &visible_node_ids {
            if let Some(node) = self.nodes.get(node_id) {
                if node.is_dir && node_id != root_id {
                    let world_p = self.custom_node_positions.get(&node_id).copied().or_else(|| calculated_positions.get(&node_id).copied());
                    if let Some(wp) = world_p {
                        let sp = transform_pos(wp);
                        let w = (165.0_f32 * self.zoom_scale).clamp(45.0_f32, 290.0_f32);
                        let h = (46.0_f32 * self.zoom_scale).clamp(20.0_f32, 80.0_f32);
                        let rect = egui::Rect::from_center_size(sp, egui::vec2(w, h));
                        if rect.contains(screen_pos) {
                            return Some(node_id);
                        }
                    }
                }
            }
        }
        None
    }
}

fn compute_hierarchical_positions(
    nodes: &[Node],
    root_id: usize,
    visible_set: &HashSet<usize>,
    canvas_center_x: f32,
    top_y: f32,
) -> HashMap<usize, egui::Pos2> {
    let mut positions = HashMap::new();
    let total_width = compute_subtree_bounds(nodes, root_id, visible_set);
    let start_left_x = canvas_center_x - (total_width / 2.0_f32);

    place_subtrees_non_overlapping(
        nodes,
        root_id,
        visible_set,
        start_left_x,
        0,
        top_y,
        &mut positions,
    );

    positions
}
