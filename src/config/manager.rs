use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::schema::{RawConfig, ResolvedConfig};

const PROJECT_CONFIG_NAMES: [&str; 4] = [
    ".moco.toml",
    ".moco/config.toml",
    ".mcps.toml",
    ".mcps/config.toml",
];

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

#[derive(Debug, Default)]
pub struct ConfigManager;

impl ConfigManager {
    #[must_use]
    pub fn find_project_config(start_dir: &Path) -> Option<PathBuf> {
        let mut current = Some(start_dir);
        while let Some(dir) = current {
            for name in PROJECT_CONFIG_NAMES {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
            current = dir.parent();
        }
        None
    }

    pub fn load_resolved(
        global_config_path: Option<&Path>,
        start_dir: &Path,
        explicit_project_config_path: Option<&Path>,
    ) -> Result<ResolvedConfig, ConfigError> {
        let mut merged = RawConfig::default();

        if let Some(path) = global_config_path {
            merged = merged.merge(Self::load_raw(path)?);
        }

        let project_path = match explicit_project_config_path {
            Some(path) => Some(path.to_path_buf()),
            None => Self::find_project_config(start_dir),
        };

        if let Some(path) = project_path {
            merged = merged.merge(Self::load_raw(&path)?);
        }

        Ok(merged.resolve())
    }

    pub fn load_raw(path: &Path) -> Result<RawConfig, ConfigError> {
        let content = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&content).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn finds_nearest_project_config() {
        let root = std::env::temp_dir().join(format!("moco-test-{}", std::process::id()));
        let project = root.join("nested/deep");
        fs::create_dir_all(&project).expect("create project dir");
        let config_path = root.join(".moco.toml");
        fs::write(&config_path, "[security]\nmode=\"enforce\"\n").expect("write config");

        let found = ConfigManager::find_project_config(&project).expect("config not found");
        assert_eq!(found, config_path);

        let _ = fs::remove_dir_all(root);
    }
}
