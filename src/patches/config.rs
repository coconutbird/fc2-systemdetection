//! Runtime patch configuration.

use std::fs;
use std::path::PathBuf;

/// Runtime switches for independently applying Dunia patches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatchConfig {
    pub jackal_tapes: bool,
    pub devmode_always_on: bool,
    pub predecessor_tapes: bool,
    pub machetes: bool,
    pub no_blinking_items: bool,
}

impl Default for PatchConfig {
    fn default() -> Self {
        Self {
            jackal_tapes: true,
            devmode_always_on: true,
            predecessor_tapes: true,
            machetes: true,
            no_blinking_items: false,
        }
    }
}

#[derive(Debug)]
pub struct ConfigLoad {
    pub config: PatchConfig,
    pub path: PathBuf,
    pub source: ConfigSource,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigSource {
    Loaded,
    MissingUsingDefaults,
    ReadFailedUsingDefaults(String),
}

impl ConfigLoad {
    pub fn load(path: PathBuf) -> Self {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let (config, warnings) = parse(&contents);
                Self {
                    config,
                    path,
                    source: ConfigSource::Loaded,
                    warnings,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                config: PatchConfig::default(),
                path,
                source: ConfigSource::MissingUsingDefaults,
                warnings: Vec::new(),
            },
            Err(error) => Self {
                config: PatchConfig::default(),
                path,
                source: ConfigSource::ReadFailedUsingDefaults(error.to_string()),
                warnings: Vec::new(),
            },
        }
    }
}

fn parse(contents: &str) -> (PatchConfig, Vec<String>) {
    let mut config = PatchConfig::default();
    let mut warnings = Vec::new();
    let mut in_patches_section = true;

    for (index, raw_line) in contents.trim_start_matches('\u{feff}').lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_patches_section = section.eq_ignore_ascii_case("patches");
            continue;
        }

        if !in_patches_section {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            warnings.push(format!("line {line_number}: expected key = value"));
            continue;
        };

        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value
            .split_once(['#', ';'])
            .map_or(raw_value, |(value, _)| value)
            .trim();

        let Some(enabled) = parse_bool(value) else {
            warnings.push(format!(
                "line {line_number}: invalid Boolean value {value:?} for {key}"
            ));
            continue;
        };

        match key.as_str() {
            "jackal_tapes" => config.jackal_tapes = enabled,
            "devmode_always_on" => config.devmode_always_on = enabled,
            "predecessor_tapes" => config.predecessor_tapes = enabled,
            "machetes" => config.machetes = enabled,
            "no_blinking_items" => config.no_blinking_items = enabled,
            _ => warnings.push(format!("line {line_number}: unknown patch option {key:?}")),
        }
    }

    (config, warnings)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn defaults_preserve_existing_runtime_behavior() {
        assert_eq!(
            PatchConfig::default(),
            PatchConfig {
                jackal_tapes: true,
                devmode_always_on: true,
                predecessor_tapes: true,
                machetes: true,
                no_blinking_items: false,
            }
        );
    }

    #[test]
    fn parses_patch_section_and_common_boolean_spellings() {
        let (config, warnings) = parse(
            "\u{feff}; comment
             [patches]
             jackal_tapes = off
             devmode_always_on = 0
             predecessor_tapes = YES
             machetes = true ; inline comment
             no_blinking_items = on # inline comment
             [ignored]
             jackal_tapes = true",
        );

        assert!(warnings.is_empty());
        assert_eq!(
            config,
            PatchConfig {
                jackal_tapes: false,
                devmode_always_on: false,
                predecessor_tapes: true,
                machetes: true,
                no_blinking_items: true,
            }
        );
    }

    #[test]
    fn invalid_lines_keep_defaults_and_return_warnings() {
        let (config, warnings) = parse(
            "[patches]
             jackal_tapes = perhaps
             unknown = true
             malformed",
        );

        assert!(config.jackal_tapes);
        assert_eq!(warnings.len(), 3);
    }

    #[test]
    fn loads_an_optional_file_and_reports_its_source() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fc2-systemdetection-{}-{unique}.ini",
            std::process::id()
        ));
        fs::write(&path, "[patches]\njackal_tapes = false\n").unwrap();

        let loaded = ConfigLoad::load(path.clone());
        let cleanup = fs::remove_file(&path);

        cleanup.unwrap();
        assert_eq!(loaded.path, path);
        assert_eq!(loaded.source, ConfigSource::Loaded);
        assert!(!loaded.config.jackal_tapes);
        assert!(loaded.warnings.is_empty());
    }
}
