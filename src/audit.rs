use petgraph::Graph;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::export::{ExportedAuditReport, ExportedNode};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Blake3,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "SHA-256"),
            HashAlgorithm::Blake3 => write!(f, "BLAKE3"),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Node {
    pub id: usize,
    pub name: String,
    pub path: PathBuf,
    pub hash_hex: String,
    pub children: Vec<usize>,
    pub parent: Option<usize>,
    pub modified_timestamp: u64,
    pub size_bytes: u64,
    pub is_dir: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub timestamp: u64,
    pub root_hash: String,
    pub target_path: String,
    pub algorithm: HashAlgorithm,
}

impl AuditRecord {
    pub fn append_to_file(&self, log_path: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        let line = format!(
            "[{}] PATH: {} | MERKLE_ROOT_{}: {}\n",
            self.timestamp, self.target_path, self.algorithm, self.root_hash
        );

        file.write_all(line.as_bytes())
    }

    pub fn to_exported_report(&self, nodes: &[Node]) -> ExportedAuditReport {
        let total_bytes: u64 = nodes.iter().map(|n| n.size_bytes).sum();
        let exported_nodes: Vec<ExportedNode> = nodes
            .iter()
            .map(|n| ExportedNode {
                id: n.id,
                name: n.name.clone(),
                path: n.path.to_string_lossy().to_string(),
                hash_hex: n.hash_hex.clone(),
                is_dir: n.is_dir,
                size_bytes: n.size_bytes,
                modified_timestamp: n.modified_timestamp,
                parent: n.parent,
                children: n.children.clone(),
            })
            .collect();

        ExportedAuditReport {
            timestamp: self.timestamp,
            root_hash: self.root_hash.clone(),
            target_path: self.target_path.clone(),
            algorithm: self.algorithm.to_string(),
            total_nodes: nodes.len(),
            total_bytes,
            nodes: exported_nodes,
        }
    }
}

pub enum WorkerMessage {
    TreeBuilt {
        nodes: Vec<Node>,
        root_id: usize,
        audit_record: AuditRecord,
    },
    Progress {
        current: usize,
        total: usize,
    },
    FileAdded(String),
    Error(String),
}

pub fn spawn_tree_builder(
    target_dir: PathBuf,
    compute_hashes: bool,
    algorithm: HashAlgorithm,
    tx: Sender<WorkerMessage>,
) {
    thread::spawn(move || {
        let mut nodes = Vec::new();
        let root_id = build_tree_structure(&target_dir, &mut nodes);

        if nodes.is_empty() {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let audit_record = AuditRecord {
                timestamp,
                root_hash: "EMPTY_DIRECTORY".to_string(),
                target_path: target_dir.to_string_lossy().to_string(),
                algorithm,
            };

            let _ = tx.send(WorkerMessage::TreeBuilt {
                nodes,
                root_id: 0,
                audit_record,
            });
            return;
        }

        if compute_hashes {
            compute_hashes_parallel(&mut nodes, algorithm, &tx);
        } else {
            for node in &mut nodes {
                node.hash_hex = "DISABLED".to_string();
            }
        }

        let root_hash = if compute_hashes && !nodes.is_empty() {
            nodes[root_id].hash_hex.clone()
        } else {
            "HASH_DISABLED_TEMPORARY".to_string()
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let audit_record = AuditRecord {
            timestamp,
            root_hash,
            target_path: target_dir.to_string_lossy().to_string(),
            algorithm,
        };

        let _ = audit_record.append_to_file("merkle_audit_ledger.log");

        let _ = tx.send(WorkerMessage::TreeBuilt {
            nodes,
            root_id,
            audit_record,
        });
    });
}

fn build_tree_structure(target_dir: &Path, nodes: &mut Vec<Node>) -> usize {
    build_node_recursive(target_dir, None, nodes)
}

fn build_node_recursive(path: &Path, parent: Option<usize>, nodes: &mut Vec<Node>) -> usize {
    let id = nodes.len();
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let is_dir = path.is_dir();

    let (modified_timestamp, size_bytes) = fs::metadata(path)
        .map(|m| {
            let modified = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let size = if m.is_file() { m.len() } else { 0 };
            (modified, size)
        })
        .unwrap_or((0, 0));

    nodes.push(Node {
        id,
        name,
        path: path.to_path_buf(),
        hash_hex: String::new(),
        children: Vec::new(),
        parent,
        modified_timestamp,
        size_bytes,
        is_dir,
    });

    let mut children_ids = Vec::new();

    if is_dir {
        if let Ok(entries) = fs::read_dir(path) {
            let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            paths.sort();
            for child_path in paths {
                let child_id = build_node_recursive(&child_path, Some(id), nodes);
                children_ids.push(child_id);
            }
        }
    }

    nodes[id].children = children_ids;
    id
}

fn compute_hashes_parallel(nodes: &mut Vec<Node>, algorithm: HashAlgorithm, tx: &Sender<WorkerMessage>) {
    let file_indices: Vec<usize> = nodes
        .iter()
        .filter(|n| !n.is_dir)
        .map(|n| n.id)
        .collect();

    let total = file_indices.len();
    let processed_count = Arc::new(AtomicUsize::new(0));

    let file_hashes: Vec<(usize, String)> = file_indices
        .par_iter()
        .map(|&idx| {
            let path = &nodes[idx].path;
            let hash = hash_single_file(path, algorithm);

            let done = processed_count.fetch_add(1, Ordering::SeqCst) + 1;
            if total > 0 && done % 10 == 0 {
                let _ = tx.send(WorkerMessage::Progress {
                    current: done,
                    total,
                });
            }

            (idx, hash)
        })
        .collect();

    for (idx, hash) in file_hashes {
        nodes[idx].hash_hex = hash;
    }

    let mut max_depth = 0;
    let mut node_depths = vec![0usize; nodes.len()];
    for i in 0..nodes.len() {
        let mut depth = 0;
        let mut curr = nodes[i].parent;
        while let Some(p) = curr {
            depth += 1;
            curr = nodes[p].parent;
        }
        node_depths[i] = depth;
        if depth > max_depth {
            max_depth = depth;
        }
    }

    for d in (0..=max_depth).rev() {
        for i in 0..nodes.len() {
            if node_depths[i] == d && nodes[i].is_dir {
                let mut combined_hashes = String::new();
                let children = nodes[i].children.clone();
                for child_id in children {
                    combined_hashes.push_str(&nodes[child_id].hash_hex);
                }
                nodes[i].hash_hex = hash_string_bytes(combined_hashes.as_bytes(), algorithm);
            }
        }
    }
}

fn hash_single_file(path: &Path, algorithm: HashAlgorithm) -> String {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return "EMPTY_OR_UNREADABLE".to_string(),
    };

    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Blake3 => {
            let hash = blake3::hash(&bytes);
            hash.to_hex().to_string()
        }
    }
}

fn hash_string_bytes(bytes: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Blake3 => {
            let hash = blake3::hash(bytes);
            hash.to_hex().to_string()
        }
    }
}

pub fn build_petgraph_from_nodes(nodes: &[Node]) -> Graph<Node, ()> {
    let mut graph = Graph::<Node, ()>::new();
    let mut node_indices = Vec::with_capacity(nodes.len());

    for node in nodes {
        let idx = graph.add_node(node.clone());
        node_indices.push(idx);
    }

    for node in nodes {
        let parent_idx = node_indices[node.id];
        for &child_id in &node.children {
            let child_idx = node_indices[child_id];
            graph.add_edge(parent_idx, child_idx, ());
        }
    }

    graph
}
