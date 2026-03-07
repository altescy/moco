use std::path::{Path, PathBuf};

pub const MOCO_DIR_NAME: &str = ".moco";
pub const CONFIG_FILE_NAME: &str = "config.toml";
pub const AUDIT_DB_FILE_NAME: &str = "audit.db";

pub const PROJECT_CONFIG_RELATIVE_PATH: &str = ".moco/config.toml";
pub const AUDIT_DB_RELATIVE_PATH: &str = ".moco/audit.db";

#[must_use]
pub fn default_project_config_path(base_dir: &Path) -> PathBuf {
    base_dir.join(PROJECT_CONFIG_RELATIVE_PATH)
}

#[must_use]
pub fn default_audit_db_path(base_dir: &Path) -> PathBuf {
    base_dir.join(AUDIT_DB_RELATIVE_PATH)
}
