use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExportedNode {
    pub id: usize,
    pub name: String,
    pub path: String,
    pub hash_hex: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub modified_timestamp: u64,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExportedAuditReport {
    pub timestamp: u64,
    pub root_hash: String,
    pub target_path: String,
    pub algorithm: String,
    pub total_nodes: usize,
    pub total_bytes: u64,
    pub nodes: Vec<ExportedNode>,
}

pub fn save_report_to_json<P: AsRef<Path>>(report: &ExportedAuditReport, destination: P) -> Result<(), String> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| format!("Error serializando a JSON: {}", e))?;

    let mut file = File::create(destination)
        .map_err(|e| format!("Error creando archivo de exportación: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Error escribiendo datos: {}", e))?;

    Ok(())
}

pub fn load_report_from_json<P: AsRef<Path>>(source: P) -> Result<ExportedAuditReport, String> {
    let content = std::fs::read_to_string(source)
        .map_err(|e| format!("Error leyendo archivo de reporte: {}", e))?;

    let report: ExportedAuditReport = serde_json::from_str(&content)
        .map_err(|e| format!("Error deserializando JSON: {}", e))?;

    Ok(report)
}
