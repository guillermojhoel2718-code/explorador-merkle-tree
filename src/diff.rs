use crate::export::ExportedAuditReport;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffStatus {
    Added,
    Removed,
    Modified { old_hash: String, new_hash: String },
    Unchanged,
}

#[derive(Debug, Clone)]
pub struct DiffItem {
    pub relative_path: String,
    pub status: DiffStatus,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TreeDiffResult {
    pub items: Vec<DiffItem>,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_modified: usize,
    pub total_unchanged: usize,
}

pub fn compare_reports(old_report: &ExportedAuditReport, new_report: &ExportedAuditReport) -> TreeDiffResult {
    let old_base = Path::new(&old_report.target_path);
    let new_base = Path::new(&new_report.target_path);

    let mut old_map: HashMap<String, (&String, bool)> = HashMap::new();
    for node in &old_report.nodes {
        let rel = Path::new(&node.path)
            .strip_prefix(old_base)
            .unwrap_or(Path::new(&node.name))
            .to_string_lossy()
            .to_string();
        old_map.insert(rel, (&node.hash_hex, node.is_dir));
    }

    let mut new_map: HashMap<String, (&String, bool)> = HashMap::new();
    for node in &new_report.nodes {
        let rel = Path::new(&node.path)
            .strip_prefix(new_base)
            .unwrap_or(Path::new(&node.name))
            .to_string_lossy()
            .to_string();
        new_map.insert(rel, (&node.hash_hex, node.is_dir));
    }

    let mut result = TreeDiffResult::default();

    for (rel, (new_hash, is_dir)) in &new_map {
        if let Some((old_hash, _)) = old_map.get(rel) {
            if old_hash == new_hash {
                result.items.push(DiffItem {
                    relative_path: rel.clone(),
                    status: DiffStatus::Unchanged,
                    is_dir: *is_dir,
                });
                result.total_unchanged += 1;
            } else {
                result.items.push(DiffItem {
                    relative_path: rel.clone(),
                    status: DiffStatus::Modified {
                        old_hash: (*old_hash).clone(),
                        new_hash: (*new_hash).clone(),
                    },
                    is_dir: *is_dir,
                });
                result.total_modified += 1;
            }
        } else {
            result.items.push(DiffItem {
                relative_path: rel.clone(),
                status: DiffStatus::Added,
                is_dir: *is_dir,
            });
            result.total_added += 1;
        }
    }

    for (rel, (_, is_dir)) in &old_map {
        if !new_map.contains_key(rel) {
            result.items.push(DiffItem {
                relative_path: rel.clone(),
                status: DiffStatus::Removed,
                is_dir: *is_dir,
            });
            result.total_removed += 1;
        }
    }

    result.items.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    result
}
