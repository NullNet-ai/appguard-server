use std::fs::create_dir;
use std::ops::Sub;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};

use crate::constants::{CONFIG_DIR, CONFIG_FILE};
use crate::error::{Error, ErrorHandler, Location};
use crate::location;

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Config {
    pub log_requests: bool,
    pub log_responses: bool,
    pub retention_sec: u64,
    pub ip_info_cache_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log_requests: true,
            log_responses: true,
            retention_sec: 0,
            ip_info_cache_size: 1000,
        }
    }
}

impl Config {
    pub fn from_file(file: &str) -> Result<Config, Error> {
        let json = std::fs::read_to_string(file).handle_err(location!())?;
        let config: Config = serde_json::from_str(&json).handle_err(location!())?;
        Ok(config)
    }
}

pub fn watch_config(config_pair: &Arc<(Mutex<Config>, Condvar)>) -> Result<(), Error> {
    create_dir(CONFIG_DIR).unwrap_or_default();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher =
        RecommendedWatcher::new(tx, notify::Config::default()).handle_err(location!())?;
    watcher
        .watch(CONFIG_DIR.as_ref(), RecursiveMode::Recursive)
        .handle_err(location!())?;

    let mut last_update_time = Instant::now().sub(Duration::from_secs(60));

    loop {
        // only update config if the event is related to a file change
        if let Ok(Ok(Event {
            kind: EventKind::Modify(_),
            ..
        })) = rx.recv()
        {
            // debounce duplicated events
            if last_update_time.elapsed().as_millis() > 100 {
                // ensure file changes are propagated
                thread::sleep(Duration::from_millis(100));

                match Config::from_file(CONFIG_FILE) {
                    Ok(new_config) => {
                        *config_pair.0.lock().handle_err(location!())? = new_config;
                        log::info!(
                            "Updated AppGuard configuration: {}",
                            serde_json::to_string(&new_config).unwrap_or_default()
                        );
                        config_pair.1.notify_all();
                    }
                    Err(_) => {
                        log::warn!("Invalid configuration definition (ignored)");
                    }
                }

                last_update_time = Instant::now();
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serial_test::parallel;

    use super::*;

    #[test]
    fn test_parse_config_file_1() {
        let config = Config::from_file("./test_material/config_test_1.json").expect("Test");
        assert_eq!(
            config,
            Config {
                log_requests: true,
                log_responses: false,
                retention_sec: 60,
                ip_info_cache_size: 999,
            }
        );
    }

    #[test]
    fn test_parse_config_file_2() {
        let config = Config::from_file("./test_material/config_test_2.json").expect("Test");
        assert_eq!(
            config,
            Config {
                log_requests: false,
                log_responses: true,
                retention_sec: 10500,
                ip_info_cache_size: 0,
            }
        );
    }

    #[test]
    #[parallel]
    fn test_watch_config() {
        // verify initial config file
        let config = Config::from_file(CONFIG_FILE).expect("Test");
        assert_eq!(config, Config::default());

        // spawn thread
        let config = Arc::new((Mutex::new(config), Condvar::new()));
        let config_clone = config.clone();
        thread::spawn(move || {
            watch_config(&config_clone).unwrap();
        });

        // write invalid config and verify it's not loaded
        std::fs::write(CONFIG_FILE, "i'm an invalid config").unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(*config.0.lock().unwrap(), Config::default());

        // write a new valid config and verify it's loaded
        std::fs::write(CONFIG_FILE, r#"{"log_requests":false,"log_responses":false,"retention_sec":12,"ip_info_cache_size":99}"#).unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(
            *config.0.lock().unwrap(),
            Config {
                log_requests: false,
                log_responses: false,
                retention_sec: 12,
                ip_info_cache_size: 99,
            }
        );

        // write the previous valid config and verify it's loaded
        std::fs::write(CONFIG_FILE, r#"{"log_requests":true,"log_responses":true,"retention_sec":0,"ip_info_cache_size":1000}"#).unwrap();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(*config.0.lock().unwrap(), Config::default());
    }
}
