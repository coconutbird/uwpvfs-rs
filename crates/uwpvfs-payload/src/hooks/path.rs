//! Path handling utilities for VFS redirection

use std::path::{Path, PathBuf};

use crate::vfshide::VfsHide;
use crate::vfsignore::VfsIgnore;

/// VFS configuration for path redirection
pub struct VfsConfig {
    /// Original game package path (e.g., C:\Program Files\WindowsApps\...)
    pub game_path: PathBuf,
    /// Mods directory path
    pub mods_path: PathBuf,
    /// Whether to log redirections
    pub log_traffic: bool,
    /// Ignore patterns loaded from .vfsignore
    pub ignore: VfsIgnore,
    /// Hide patterns loaded from .vfshide
    pub hide: VfsHide,
}

/// Check if a path should be hidden (return file not found)
/// Only hides original game files - if a mod file exists at that path, it won't be hidden
pub fn should_hide_path(config: &VfsConfig, original_path: &str) -> bool {
    // Normalize to absolute DOS path
    let abs_path = normalize_to_absolute(original_path);

    // Skip device paths we couldn't convert
    if abs_path.starts_with("\\Device\\") {
        return false;
    }

    // Normalize path separators for consistent comparison
    let abs_path = normalize_path_separators(&abs_path);
    let path_lower = abs_path.to_lowercase();

    // Normalize game path
    let game_path_str = normalize_path_separators(&config.game_path.to_string_lossy());
    let game_path_lower = game_path_str.to_lowercase();

    // Check if path is within game directory
    if !path_lower.starts_with(&game_path_lower) {
        return false;
    }

    // Extract relative path
    let relative = &abs_path[game_path_str.len()..].trim_start_matches('\\');

    // Check if relative path matches any hide patterns
    if !config.hide.is_hidden(relative) {
        return false;
    }

    // Only hide if there's NO mod file at this path
    // If a mod file exists, we want to redirect to it instead of hiding
    let mod_path = config.mods_path.join(relative);
    !mod_path.exists()
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

/// Check if a path should be redirected and return the redirected path.
/// - `for_write`: If true, redirects even if mod file doesn't exist (for write operations)
pub fn get_redirected_path_ex(
    config: &VfsConfig,
    original_path: &str,
    for_write: bool,
) -> Option<PathBuf> {
    get_redirected_path_internal(config, original_path, false, for_write)
}

/// Check if a path should be redirected (for reads only).
/// Only redirects if the mod file already exists.
#[cfg(test)]
pub fn get_redirected_path(config: &VfsConfig, original_path: &str) -> Option<PathBuf> {
    get_redirected_path_internal(config, original_path, false, false)
}

/// Normalize path separators to backslashes and remove trailing slashes
fn normalize_path_separators(path: &str) -> String {
    let normalized = path.replace('/', "\\");
    normalized.trim_end_matches('\\').to_string()
}

/// Internal implementation with options for DLLs and write mode
fn get_redirected_path_internal(
    config: &VfsConfig,
    original_path: &str,
    allow_dll: bool,
    for_write: bool,
) -> Option<PathBuf> {
    // Normalize to absolute DOS path
    let abs_path = normalize_to_absolute(original_path);

    // Skip device paths we couldn't convert
    if abs_path.starts_with("\\Device\\") {
        return None;
    }

    // Normalize path separators for consistent comparison
    let abs_path = normalize_path_separators(&abs_path);
    let path_lower = abs_path.to_lowercase();

    // Skip DLL and EXE files to avoid integrity check issues (unless allow_dll is true)
    if !allow_dll && (path_lower.ends_with(".dll") || path_lower.ends_with(".exe")) {
        return None;
    }

    // Check if this path is within the game directory
    // Normalize game path too for consistent comparison
    let game_path_str = normalize_path_separators(&config.game_path.to_string_lossy());
    let game_path_lower = game_path_str.to_lowercase();

    // Need to check with trailing backslash to avoid matching partial directory names
    // e.g., "C:\Game" should not match "C:\GameData\file.txt"
    let game_path_prefix = if game_path_lower.ends_with('\\') {
        game_path_lower.clone()
    } else {
        format!("{}\\", game_path_lower)
    };

    if !path_lower.starts_with(&game_path_prefix) && path_lower != game_path_lower {
        return None;
    }

    // Get relative path from game directory
    let relative = if path_lower == game_path_lower {
        ""
    } else {
        // Use the prefix length (with backslash) to get relative path
        &abs_path[game_path_prefix.len().min(abs_path.len())..]
    };
    let relative = relative.trim_start_matches(['\\', '/']);

    // Check if this path is excluded by .vfsignore
    if !relative.is_empty() && config.ignore.is_ignored(relative) {
        return None;
    }

    // Build the modded path
    let modded_path = config.mods_path.join(relative);

    // For writes, always redirect to mods folder (file will be created)
    // For reads, only redirect if the mod file already exists
    if for_write {
        // Copy-on-write: if mod file doesn't exist but game file does,
        // copy the game file to mods folder first. This ensures read+write
        // operations can read existing content before modifying.
        if !modded_path.exists() {
            let game_file = config.game_path.join(relative);
            if game_file.exists() && game_file.is_file() {
                // Ensure parent directory exists
                if let Some(parent) = modded_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                // Copy the file (ignore errors - file will be created fresh if copy fails)
                let _ = std::fs::copy(&game_file, &modded_path);
            }
        }
        Some(modded_path)
    } else if modded_path.exists() {
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
    use crate::vfshide::VfsHide;
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
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
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
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
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
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
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
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
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
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
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
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
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
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
        };

        // NT path format should work
        let game_file_nt = format!("\\??\\{}", game_path.join("data.pak").display());
        let result = get_redirected_path(&config, &game_file_nt);

        assert!(result.is_some(), "Expected redirect for NT path format");
        assert_eq!(result.unwrap(), mod_file);
    }

    #[test]
    fn test_get_redirected_path_respects_vfsignore() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create mod files
        let mod_texture = mods_path.join("textures");
        fs::create_dir_all(&mod_texture).unwrap();
        fs::write(mod_texture.join("hero.pak"), "modded texture").unwrap();

        let mod_saves = mods_path.join("saves");
        fs::create_dir_all(&mod_saves).unwrap();
        fs::write(mod_saves.join("slot1.sav"), "save data").unwrap();

        // Create .vfsignore that excludes saves
        let ignore = VfsIgnore::parse("saves/**").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore,
            hide: VfsHide::empty(),
        };

        // Texture should be redirected (not ignored)
        let game_texture = game_path.join("textures\\hero.pak");
        let result = get_redirected_path(&config, &game_texture.to_string_lossy());
        assert!(result.is_some(), "Expected redirect for non-ignored file");

        // Save should NOT be redirected (ignored by .vfsignore)
        let game_save = game_path.join("saves\\slot1.sav");
        let result = get_redirected_path(&config, &game_save.to_string_lossy());
        assert!(result.is_none(), "Expected no redirect for ignored file");
    }

    #[test]
    fn test_get_redirected_path_vfsignore_wildcard() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create mod files
        fs::write(mods_path.join("data.pak"), "mod data").unwrap();
        fs::write(mods_path.join("debug.log"), "log content").unwrap();

        // Create .vfsignore that excludes all .log files
        let ignore = VfsIgnore::parse("*.log").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore,
            hide: VfsHide::empty(),
        };

        // .pak should be redirected
        let game_pak = game_path.join("data.pak");
        let result = get_redirected_path(&config, &game_pak.to_string_lossy());
        assert!(result.is_some(), "Expected redirect for .pak file");

        // .log should NOT be redirected
        let game_log = game_path.join("debug.log");
        let result = get_redirected_path(&config, &game_log.to_string_lossy());
        assert!(result.is_none(), "Expected no redirect for .log file");
    }

    #[test]
    fn test_vfshide_only_hides_original_files() {
        // Create temp directories for game and mods
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create .vfshide that hides intro.mp4
        let hide = VfsHide::parse("intro.mp4").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore: VfsIgnore::empty(),
            hide,
        };

        // intro.mp4 in game dir should be hidden (no mod replacement)
        let game_intro = game_path.join("intro.mp4");
        assert!(
            should_hide_path(&config, &game_intro.to_string_lossy()),
            "Expected intro.mp4 to be hidden when no mod file exists"
        );

        // Now create a mod file that replaces intro.mp4
        let mod_intro = mods_path.join("intro.mp4");
        fs::write(&mod_intro, "mod intro").unwrap();

        // intro.mp4 should NOT be hidden anymore (mod file exists)
        assert!(
            !should_hide_path(&config, &game_intro.to_string_lossy()),
            "Expected intro.mp4 to NOT be hidden when mod file exists"
        );
    }

    #[test]
    fn test_vfshide_does_not_hide_outside_game_dir() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        let hide = VfsHide::parse("intro.mp4").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore: VfsIgnore::empty(),
            hide,
        };

        // intro.mp4 outside game dir should NOT be hidden
        let other_intro = temp.path().join("other").join("intro.mp4");
        assert!(
            !should_hide_path(&config, &other_intro.to_string_lossy()),
            "Expected intro.mp4 outside game dir to NOT be hidden"
        );
    }

    #[test]
    fn test_copy_on_write_for_existing_game_file() {
        // Create temp directories for game and mods
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create a game file (but no mod file)
        let game_file = game_path.join("save.dat");
        fs::write(&game_file, "original save data").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
        };

        // For read-only, should NOT redirect (no mod file exists)
        let result = get_redirected_path(&config, &game_file.to_string_lossy());
        assert!(
            result.is_none(),
            "Read-only should not redirect when no mod file"
        );

        // For write, should redirect AND copy the game file
        let result = get_redirected_path_ex(&config, &game_file.to_string_lossy(), true);
        assert!(result.is_some(), "Write should redirect");

        let mod_file = mods_path.join("save.dat");
        assert!(
            mod_file.exists(),
            "Mod file should be created via copy-on-write"
        );

        // Verify the content was copied
        let content = fs::read_to_string(&mod_file).unwrap();
        assert_eq!(
            content, "original save data",
            "Content should be copied from game file"
        );
    }

    #[test]
    fn test_copy_on_write_creates_parent_dirs() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create a game file in a subdirectory
        let game_subdir = game_path.join("saves").join("slot1");
        fs::create_dir_all(&game_subdir).unwrap();
        let game_file = game_subdir.join("data.sav");
        fs::write(&game_file, "save slot 1").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
        };

        // Write should create parent dirs and copy
        let result = get_redirected_path_ex(&config, &game_file.to_string_lossy(), true);
        assert!(result.is_some());

        let mod_file = mods_path.join("saves").join("slot1").join("data.sav");
        assert!(
            mod_file.exists(),
            "Mod file should exist with parent dirs created"
        );
        assert_eq!(fs::read_to_string(&mod_file).unwrap(), "save slot 1");
    }

    #[test]
    fn test_copy_on_write_skips_if_mod_exists() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        // Create both game and mod files with different content
        let game_file = game_path.join("config.ini");
        let mod_file = mods_path.join("config.ini");
        fs::write(&game_file, "original config").unwrap();
        fs::write(&mod_file, "modded config").unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
        };

        // Write should redirect to existing mod file without overwriting
        let result = get_redirected_path_ex(&config, &game_file.to_string_lossy(), true);
        assert!(result.is_some());

        // Mod file should still have modded content (not overwritten)
        assert_eq!(fs::read_to_string(&mod_file).unwrap(), "modded config");
    }

    #[test]
    fn test_copy_on_write_no_game_file() {
        let temp = TempDir::new().unwrap();
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");

        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore: VfsIgnore::empty(),
            hide: VfsHide::empty(),
        };

        // Write to a file that doesn't exist in game dir either
        let new_file = game_path.join("newsave.dat");
        let result = get_redirected_path_ex(&config, &new_file.to_string_lossy(), true);
        assert!(
            result.is_some(),
            "Should still redirect for new file creation"
        );

        // Mod file should NOT exist yet (nothing to copy, game will create it)
        let mod_file = mods_path.join("newsave.dat");
        assert!(
            !mod_file.exists(),
            "No copy should happen when game file doesn't exist"
        );
    }
}
