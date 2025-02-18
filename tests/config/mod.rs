use appguard_server::config::Config;
use appguard_server::constants::CONFIG_FILE;

pub fn write_config_to_file(config: &Config) {
    let json = serde_json::to_string(&config).unwrap();
    std::fs::write(CONFIG_FILE, json).unwrap();

    assert_eq!(Config::from_file(CONFIG_FILE).unwrap(), *config);
}
