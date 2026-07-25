use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc::Sender;

pub enum WatcherMessage {
    FileChanged(PathBuf, String),
    Error(String),
}

pub struct FileWatcher {
    _watcher: RecommendedWatcher,
}

impl FileWatcher {
    pub fn start(target_path: PathBuf, tx: Sender<WatcherMessage>) -> Result<Self, String> {
        let (event_tx, event_rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                let _ = event_tx.send(res);
            },
            Config::default(),
        )
        .map_err(|e| format!("Failed to create watcher: {}", e))?;

        watcher
            .watch(&target_path, RecursiveMode::Recursive)
            .map_err(|e| format!("Failed to watch directory: {}", e))?;

        std::thread::spawn(move || {
            while let Ok(res) = event_rx.recv() {
                match res {
                    Ok(event) => match event.kind {
                        EventKind::Create(_) => {
                            for path in event.paths {
                                let _ = tx.send(WatcherMessage::FileChanged(
                                    path.clone(),
                                    format!("Archivo Creado: {}", path.display()),
                                ));
                            }
                        }
                        EventKind::Modify(_) => {
                            for path in event.paths {
                                let _ = tx.send(WatcherMessage::FileChanged(
                                    path.clone(),
                                    format!("Archivo Modificado: {}", path.display()),
                                ));
                            }
                        }
                        EventKind::Remove(_) => {
                            for path in event.paths {
                                let _ = tx.send(WatcherMessage::FileChanged(
                                    path.clone(),
                                    format!("Archivo Eliminado: {}", path.display()),
                                ));
                            }
                        }
                        _ => {}
                    },
                    Err(e) => {
                        let _ = tx.send(WatcherMessage::Error(format!("Watcher Error: {}", e)));
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }
}
