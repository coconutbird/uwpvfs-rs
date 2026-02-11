//! Directory handle tracking for VFS directory enumeration
//!
//! Tracks which open directory handles correspond to game directories
//! so we can inject mod files during directory enumeration.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use windows::Win32::Foundation::HANDLE;

use super::path::VfsConfig;

/// Tracked state for a game directory handle
pub struct TrackedDir {
    /// The game directory path (stored for debugging/logging)
    #[allow(dead_code)]
    pub game_path: PathBuf,
    /// The corresponding mods directory path (stored for debugging/logging)
    #[allow(dead_code)]
    pub mods_path: PathBuf,
    /// Files from mods directory that haven't been returned yet
    pub pending_mod_files: Vec<ModFileEntry>,
    /// Files we've already returned (to avoid duplicates)
    pub returned_files: HashSet<String>,
}

/// A mod file entry to inject into directory listing
#[derive(Clone)]
pub struct ModFileEntry {
    pub name: String,
    pub size: u64,
    pub creation_time: i64,
    pub last_write_time: i64,
    pub attributes: u32,
}

/// Global map of directory handles to tracked state
static DIR_HANDLES: Mutex<Option<HashMap<isize, TrackedDir>>> = Mutex::new(None);

/// Initialize the directory tracking system
pub fn init() {
    let mut guard = DIR_HANDLES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

/// Register a directory handle for tracking if it's a game directory
pub fn register_handle(handle: HANDLE, path: &str, config: &VfsConfig) {
    let path_lower = path.to_lowercase();
    let game_path_lower = config.game_path.to_string_lossy().to_lowercase();

    // Check if this is within the game directory
    if !path_lower.starts_with(&game_path_lower) {
        return;
    }

    // Calculate relative path from game dir
    let rel_path = &path[game_path_lower.len()..].trim_start_matches(['\\', '/']);
    let mods_subpath = config.mods_path.join(rel_path);

    // Only track if the mods directory exists
    if !mods_subpath.exists() || !mods_subpath.is_dir() {
        return;
    }

    // Enumerate mod files
    let mod_files = enumerate_mod_files(&mods_subpath);
    if mod_files.is_empty() {
        return;
    }

    let tracked = TrackedDir {
        game_path: PathBuf::from(path),
        mods_path: mods_subpath,
        pending_mod_files: mod_files,
        returned_files: HashSet::new(),
    };

    let mut guard = DIR_HANDLES.lock().unwrap();
    if let Some(map) = guard.as_mut() {
        map.insert(handle.0 as isize, tracked);
    }
}

/// Unregister a directory handle (for future use when tracking handle close)
#[allow(dead_code)]
pub fn unregister_handle(handle: HANDLE) {
    let mut guard = DIR_HANDLES.lock().unwrap();
    if let Some(map) = guard.as_mut() {
        map.remove(&(handle.0 as isize));
    }
}

/// Get tracked directory info for a handle
pub fn get_tracked(handle: HANDLE) -> Option<TrackedDirGuard> {
    let guard = DIR_HANDLES.lock().ok()?;
    if guard.as_ref()?.contains_key(&(handle.0 as isize)) {
        Some(TrackedDirGuard { handle })
    } else {
        None
    }
}

/// Guard that provides access to tracked directory state
pub struct TrackedDirGuard {
    handle: HANDLE,
}

impl TrackedDirGuard {
    /// Mark a file as returned (so we don't inject duplicates)
    pub fn mark_returned(&self, filename: &str) {
        let mut guard = DIR_HANDLES.lock().unwrap();
        if let Some(map) = guard.as_mut()
            && let Some(tracked) = map.get_mut(&(self.handle.0 as isize))
        {
            tracked.returned_files.insert(filename.to_lowercase());
        }
    }

    /// Get the next pending mod file that hasn't been returned
    pub fn next_pending_mod_file(&self) -> Option<ModFileEntry> {
        let mut guard = DIR_HANDLES.lock().unwrap();
        let map = guard.as_mut()?;
        let tracked = map.get_mut(&(self.handle.0 as isize))?;

        while let Some(entry) = tracked.pending_mod_files.pop() {
            let name_lower = entry.name.to_lowercase();
            if !tracked.returned_files.contains(&name_lower) {
                tracked.returned_files.insert(name_lower);
                return Some(entry);
            }
        }
        None
    }

    /// Check if there are pending mod files
    #[allow(dead_code)]
    pub fn has_pending(&self) -> bool {
        let guard = DIR_HANDLES.lock().ok();
        guard
            .as_ref()
            .and_then(|g| g.as_ref())
            .and_then(|map| map.get(&(self.handle.0 as isize)))
            .map(|t| !t.pending_mod_files.is_empty())
            .unwrap_or(false)
    }
}

/// Enumerate files in a mod directory
fn enumerate_mod_files(path: &PathBuf) -> Vec<ModFileEntry> {
    let mut entries = Vec::new();

    let Ok(read_dir) = std::fs::read_dir(path) else {
        return entries;
    };

    for entry in read_dir.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };

        let name = entry.file_name().to_string_lossy().to_string();

        // Skip VFS config files
        if name == ".vfsignore" || name == ".vfshide" {
            continue;
        }

        let attributes = if metadata.is_dir() {
            0x10 // FILE_ATTRIBUTE_DIRECTORY
        } else {
            0x80 // FILE_ATTRIBUTE_NORMAL
        };

        // Convert SystemTime to Windows FILETIME (100ns intervals since 1601)
        let to_filetime = |time: std::io::Result<std::time::SystemTime>| -> i64 {
            time.ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| {
                    // FILETIME epoch is 1601, UNIX epoch is 1970
                    // Difference is 11644473600 seconds
                    const EPOCH_DIFF: i64 = 11644473600;
                    ((d.as_secs() as i64 + EPOCH_DIFF) * 10_000_000)
                        + (d.subsec_nanos() as i64 / 100)
                })
                .unwrap_or(0)
        };

        entries.push(ModFileEntry {
            name,
            size: metadata.len(),
            creation_time: to_filetime(metadata.created()),
            last_write_time: to_filetime(metadata.modified()),
            attributes,
        });
    }

    entries
}

/// Cleanup directory tracking
pub fn cleanup() {
    let mut guard = DIR_HANDLES.lock().unwrap();
    *guard = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::fs;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    // Mutex to serialize tests since they share global state
    static TEST_MUTEX: StdMutex<()> = StdMutex::new(());

    /// Create a fake HANDLE for testing (just a unique pointer value)
    fn fake_handle(id: usize) -> HANDLE {
        HANDLE(id as *mut c_void)
    }

    fn create_test_config(temp: &TempDir) -> (PathBuf, PathBuf, VfsConfig) {
        let game_path = temp.path().join("game");
        let mods_path = temp.path().join("mods");
        fs::create_dir_all(&game_path).unwrap();
        fs::create_dir_all(&mods_path).unwrap();

        let config = VfsConfig {
            game_path: game_path.clone(),
            mods_path: mods_path.clone(),
            log_traffic: false,
            ignore: crate::vfsignore::VfsIgnore::empty(),
            hide: crate::vfshide::VfsHide::empty(),
        };

        (game_path, mods_path, config)
    }

    #[test]
    fn test_init_and_cleanup() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup(); // Ensure clean state

        init();
        {
            let guard = DIR_HANDLES.lock().unwrap();
            assert!(guard.is_some());
        }

        cleanup();
        {
            let guard = DIR_HANDLES.lock().unwrap();
            assert!(guard.is_none());
        }
    }

    #[test]
    fn test_register_handle_outside_game_dir() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (_, _, config) = create_test_config(&temp);

        // Try to register a handle for a path outside game dir
        let handle = fake_handle(12345);
        register_handle(handle, "C:\\SomeOtherPath\\dir", &config);

        // Should not be tracked
        assert!(get_tracked(handle).is_none());
    }

    #[test]
    fn test_register_handle_no_mods_dir() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (game_path, _, config) = create_test_config(&temp);

        // Create a subdir in game but NOT in mods
        let game_subdir = game_path.join("subdir");
        fs::create_dir_all(&game_subdir).unwrap();

        let handle = fake_handle(12345);
        register_handle(handle, &game_subdir.to_string_lossy(), &config);

        // Should not be tracked (no corresponding mods dir)
        assert!(get_tracked(handle).is_none());
    }

    #[test]
    fn test_register_handle_with_mod_files() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (game_path, mods_path, config) = create_test_config(&temp);

        // Create matching subdirs
        let game_subdir = game_path.join("data");
        let mods_subdir = mods_path.join("data");
        fs::create_dir_all(&game_subdir).unwrap();
        fs::create_dir_all(&mods_subdir).unwrap();

        // Create mod files
        fs::write(mods_subdir.join("mod1.pak"), "content1").unwrap();
        fs::write(mods_subdir.join("mod2.pak"), "content2").unwrap();

        let handle = fake_handle(12345);
        register_handle(handle, &game_subdir.to_string_lossy(), &config);

        // Should be tracked
        let tracked = get_tracked(handle);
        assert!(tracked.is_some());
    }

    #[test]
    fn test_mark_returned_and_next_pending() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (game_path, mods_path, config) = create_test_config(&temp);

        // Create matching subdirs
        let game_subdir = game_path.join("data");
        let mods_subdir = mods_path.join("data");
        fs::create_dir_all(&game_subdir).unwrap();
        fs::create_dir_all(&mods_subdir).unwrap();

        // Create mod files
        fs::write(mods_subdir.join("mod1.pak"), "content1").unwrap();
        fs::write(mods_subdir.join("mod2.pak"), "content2").unwrap();

        let handle = fake_handle(12345);
        register_handle(handle, &game_subdir.to_string_lossy(), &config);

        let tracked = get_tracked(handle).unwrap();

        // Mark one file as already returned (simulating game enumeration)
        tracked.mark_returned("mod1.pak");

        // Get next pending - should skip mod1.pak
        let next = tracked.next_pending_mod_file();
        assert!(next.is_some());
        let entry = next.unwrap();
        assert_eq!(entry.name.to_lowercase(), "mod2.pak");

        // No more pending
        let next = tracked.next_pending_mod_file();
        assert!(next.is_none());
    }

    #[test]
    fn test_enumerate_mod_files_skips_vfs_config() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (game_path, mods_path, config) = create_test_config(&temp);

        // Create mod files including VFS config files
        fs::write(mods_path.join("mod.pak"), "content").unwrap();
        fs::write(mods_path.join(".vfsignore"), "*.dll").unwrap();
        fs::write(mods_path.join(".vfshide"), "intro.mp4").unwrap();

        let handle = fake_handle(12345);
        register_handle(handle, &game_path.to_string_lossy(), &config);

        let tracked = get_tracked(handle).unwrap();

        // Should only get mod.pak, not the config files
        let entry = tracked.next_pending_mod_file();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().name, "mod.pak");

        // No more files
        assert!(tracked.next_pending_mod_file().is_none());
    }

    #[test]
    fn test_unregister_handle() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (game_path, mods_path, config) = create_test_config(&temp);

        fs::write(mods_path.join("mod.pak"), "content").unwrap();

        let handle = fake_handle(12345);
        register_handle(handle, &game_path.to_string_lossy(), &config);
        assert!(get_tracked(handle).is_some());

        unregister_handle(handle);
        assert!(get_tracked(handle).is_none());
    }

    #[test]
    fn test_case_insensitive_duplicate_detection() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (game_path, mods_path, config) = create_test_config(&temp);

        // Create mod file
        fs::write(mods_path.join("Data.pak"), "content").unwrap();

        let handle = fake_handle(12345);
        register_handle(handle, &game_path.to_string_lossy(), &config);

        let tracked = get_tracked(handle).unwrap();

        // Mark with different case - should still prevent duplicate
        tracked.mark_returned("DATA.PAK");

        // Should not return the file (case-insensitive match)
        assert!(tracked.next_pending_mod_file().is_none());
    }

    #[test]
    fn test_mod_file_entry_attributes() {
        let _lock = TEST_MUTEX.lock().unwrap();
        cleanup();
        init();

        let temp = TempDir::new().unwrap();
        let (game_path, mods_path, config) = create_test_config(&temp);

        // Create a file and a directory
        fs::write(mods_path.join("file.pak"), "file content").unwrap();
        fs::create_dir(mods_path.join("subdir")).unwrap();

        let handle = fake_handle(12345);
        register_handle(handle, &game_path.to_string_lossy(), &config);

        let tracked = get_tracked(handle).unwrap();

        // Get both entries
        let mut entries = Vec::new();
        while let Some(entry) = tracked.next_pending_mod_file() {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 2);

        // Find file and dir entries
        let file_entry = entries.iter().find(|e| e.name == "file.pak").unwrap();
        let dir_entry = entries.iter().find(|e| e.name == "subdir").unwrap();

        // Check attributes
        assert_eq!(file_entry.attributes, 0x80); // FILE_ATTRIBUTE_NORMAL
        assert_eq!(file_entry.size, 12); // "file content".len()

        assert_eq!(dir_entry.attributes, 0x10); // FILE_ATTRIBUTE_DIRECTORY
    }
}
