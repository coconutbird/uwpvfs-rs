//! Path handling utilities for VFS redirection

use std::path::{Path, PathBuf};

/// VFS configuration for path redirection
pub struct VfsConfig {
    /// Original game package path (e.g., C:\Program Files\WindowsApps\...)
    pub game_path: PathBuf,
    /// Mods directory path
    pub mods_path: PathBuf,
    /// Whether to log redirections
    pub log_traffic: bool,
}

/// Convert a path to absolute DOS path
/// Handles NT paths (\??\C:\...), device paths, and relative paths
pub fn normalize_to_absolute(path: &str) -> String {
    // Strip NT path prefix if present
    let dos_path = if let Some(stripped) = path.strip_prefix("\\??\\") {
        stripped
    } else if path.starts_with("\\Device\\") {
        // Can't easily convert device paths, return as-is
        return path.to_string();
    } else {
        path
    };

    // If it's already an absolute path (has drive letter), return it
    if dos_path.len() >= 2 && dos_path.chars().nth(1) == Some(':') {
        return dos_path.to_string();
    }

    // It's a relative path - get current directory and prepend it
    // Use std::env::current_dir() which doesn't require the file to exist
    if let Ok(cwd) = std::env::current_dir() {
        let full_path = cwd.join(dos_path);
        return full_path.to_string_lossy().to_string();
    }

    // Fallback: return as-is
    dos_path.to_string()
}

/// Check if a path should be redirected and return the redirected path
pub fn get_redirected_path(config: &VfsConfig, original_path: &str) -> Option<PathBuf> {
    // Normalize to absolute DOS path
    let abs_path = normalize_to_absolute(original_path);

    // Skip device paths we couldn't convert
    if abs_path.starts_with("\\Device\\") {
        return None;
    }

    // Skip DLL and EXE files to avoid integrity check issues
    let path_lower = abs_path.to_lowercase();
    if path_lower.ends_with(".dll") || path_lower.ends_with(".exe") {
        return None;
    }

    // Check if this path is within the game directory
    let game_path_str = config.game_path.to_string_lossy();
    if !path_lower.starts_with(&game_path_str.to_lowercase()) {
        return None;
    }

    // Get relative path from game directory
    let relative = &abs_path[game_path_str.len()..];
    let relative = relative.trim_start_matches(['\\', '/']);

    // Check if the modded file exists
    let modded_path = config.mods_path.join(relative);
    if modded_path.exists() {
        Some(modded_path)
    } else {
        None
    }
}

/// Create NT path format from a DOS path
pub fn to_nt_path(path: &Path) -> String {
    format!("\\??\\{}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_normalize_nt_path_prefix() {
        // NT path with \??\ prefix should have it stripped
        let result = normalize_to_absolute("\\??\\C:\\Program Files\\Game\\data.pak");
        assert_eq!(result, "C:\\Program Files\\Game\\data.pak");
    }

    #[test]
    fn test_normalize_device_path_unchanged() {
        // Device paths should be returned as-is
        let result = normalize_to_absolute("\\Device\\HarddiskVolume3\\Game\\data.pak");
        assert_eq!(result, "\\Device\\HarddiskVolume3\\Game\\data.pak");
    }

    #[test]
    fn test_normalize_absolute_path_unchanged() {
        // Absolute DOS paths should be returned as-is
        let result = normalize_to_absolute("C:\\Program Files\\Game\\data.pak");
        assert_eq!(result, "C:\\Program Files\\Game\\data.pak");
    }

    #[test]
    fn test_normalize_relative_path_becomes_absolute() {
        // Relative paths should be joined with current directory
        let result = normalize_to_absolute("data\\sound\\file.pck");

        // Should start with a drive letter
        assert!(
            result.chars().nth(1) == Some(':'),
            "Expected absolute path, got: {}",
            result
        );
        // Should end with the relative path
        assert!(
            result.ends_with("data\\sound\\file.pck"),
            "Expected path to end with relative part, got: {}",
            result
        );
    }

    #[test]
    fn test_to_nt_path() {
        let path = Path::new("C:\\Users\\test\\mods\\file.pak");
        let result = to_nt_path(path);
        assert_eq!(result, "\\??\\C:\\Users\\test\\mods\\file.pak");
    }

    #[test]
    fn test_get_redirected_path_in_game_dir_with_mod() {
        // Create temp directories for game and mods
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create a mod file
        let mod_file = mods_path.join("data.pak");
        fs::write(&mod_file, "mod content").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
        };

        // Request for game file should redirect to mod
        let game_file = game_path.join("data.pak");
        let result = get_redirected_path(&config, &game_file.to_string_lossy());

        assert!(result.is_some(), "Expected redirect for existing mod file");
        assert_eq!(result.unwrap(), mod_file);
    }

    #[test]
    fn test_get_redirected_path_no_mod_file() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();
        // Don't create mod file

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
        };

        let game_file = game_path.join("data.pak");
        let result = get_redirected_path(&config, &game_file.to_string_lossy());

        assert!(
            result.is_none(),
            "Expected no redirect when mod file doesn't exist"
        );
    }

    #[test]
    fn test_get_redirected_path_outside_game_dir() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
        };

        // Path outside game directory should not redirect
        let other_file = temp.path().join("other\\file.pak");
        let result = get_redirected_path(&config, &other_file.to_string_lossy());

        assert!(
            result.is_none(),
            "Expected no redirect for path outside game dir"
        );
    }

    #[test]
    fn test_get_redirected_path_skips_dll() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create a mod DLL
        let mod_dll = mods_path.join("plugin.dll");
        fs::write(&mod_dll, "fake dll").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
        };

        let game_dll = game_path.join("plugin.dll");
        let result = get_redirected_path(&config, &game_dll.to_string_lossy());

        assert!(result.is_none(), "Expected no redirect for DLL files");
    }

    #[test]
    fn test_get_redirected_path_skips_exe() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create a mod EXE
        let mod_exe = mods_path.join("game.exe");
        fs::write(&mod_exe, "fake exe").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
        };

        let game_exe = game_path.join("game.exe");
        let result = get_redirected_path(&config, &game_exe.to_string_lossy());

        assert!(result.is_none(), "Expected no redirect for EXE files");
    }

    #[test]
    fn test_get_redirected_path_device_path_skipped() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
        };

        // Device paths should be skipped
        let result = get_redirected_path(&config, "\\Device\\HarddiskVolume3\\data.pak");

        assert!(result.is_none(), "Expected no redirect for device paths");
    }

    #[test]
    fn test_get_redirected_path_with_nt_prefix() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create a mod file
        let mod_file = mods_path.join("data.pak");
        fs::write(&mod_file, "mod content").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
        };

        // NT path format should work
        let game_file_nt = format!("\\??\\{}", game_path.join("data.pak").display());
        let result = get_redirected_path(&config, &game_file_nt);

        assert!(result.is_some(), "Expected redirect for NT path format");
        assert_eq!(result.unwrap(), mod_file);
    }
}
