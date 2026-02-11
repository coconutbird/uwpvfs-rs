//! VFS ignore file parsing and matching
//!
//! Provides gitignore-style pattern matching for excluding files from VFS redirection.
//! The `.vfsignore` file should be placed in the mods folder root.
//!
//! # Syntax
//!
//! - Lines starting with `#` are comments
//! - Empty lines are ignored
//! - Patterns use glob syntax (`*`, `**`, `?`)
//! - Patterns are matched against the relative path from the game/mods folder
//!
//! # Example `.vfsignore`
//!
//! ```text
//! # Don't redirect save files
//! saves/**
//!
//! # Don't redirect log files
//! *.log
//! logs/
//! ```

use crate::patterns::{PatternError, PatternSet};
use std::path::Path;

/// Name of the ignore file
pub const VFSIGNORE_FILENAME: &str = ".vfsignore";

/// Parsed vfsignore rules for pattern matching
#[derive(Debug)]
pub struct VfsIgnore(PatternSet);

impl Default for VfsIgnore {
    fn default() -> Self {
        Self::empty()
    }
}

impl VfsIgnore {
    /// Create an empty ignore set (matches nothing)
    pub fn empty() -> Self {
        Self(PatternSet::empty())
    }

    /// Load and parse a .vfsignore file from the given mods directory
    pub fn load(mods_path: &Path) -> Result<Self, PatternError> {
        Ok(Self(PatternSet::load(mods_path, VFSIGNORE_FILENAME)?))
    }

    /// Parse vfsignore content from a string
    pub fn parse(content: &str) -> Result<Self, PatternError> {
        Ok(Self(PatternSet::parse(content)?))
    }

    /// Check if a relative path should be ignored (excluded from redirection)
    pub fn is_ignored(&self, relative_path: &str) -> bool {
        self.0.is_match(relative_path)
    }

    /// Get the number of patterns loaded
    pub fn pattern_count(&self) -> usize {
        self.0.pattern_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_ignore() {
        let ignore = VfsIgnore::empty();
        assert_eq!(ignore.pattern_count(), 0);
        assert!(!ignore.is_ignored("any/path.txt"));
    }

    #[test]
    fn test_parse_empty_content() {
        let ignore = VfsIgnore::parse("").unwrap();
        assert_eq!(ignore.pattern_count(), 0);
    }

    #[test]
    fn test_parse_comments_only() {
        let content = "# This is a comment\n# Another comment\n";
        let ignore = VfsIgnore::parse(content).unwrap();
        assert_eq!(ignore.pattern_count(), 0);
    }

    #[test]
    fn test_parse_simple_pattern() {
        let content = "*.log";
        let ignore = VfsIgnore::parse(content).unwrap();
        assert_eq!(ignore.pattern_count(), 1);
        assert!(ignore.is_ignored("debug.log"));
        assert!(ignore.is_ignored("error.LOG")); // case insensitive
        assert!(!ignore.is_ignored("debug.txt"));
    }

    #[test]
    fn test_parse_directory_pattern() {
        let content = "saves/";
        let ignore = VfsIgnore::parse(content).unwrap();
        assert!(ignore.is_ignored("saves/slot1.sav"));
        assert!(ignore.is_ignored("saves/backup/slot1.sav"));
        assert!(!ignore.is_ignored("data/saves.pak"));
    }

    #[test]
    fn test_parse_glob_star_pattern() {
        let content = "data/saves/**";
        let ignore = VfsIgnore::parse(content).unwrap();
        assert!(ignore.is_ignored("data/saves/slot1.sav"));
        assert!(ignore.is_ignored("data/saves/backup/slot1.sav"));
        assert!(!ignore.is_ignored("data/textures/hero.pak"));
    }

    #[test]
    fn test_backslash_paths() {
        let content = "saves/**";
        let ignore = VfsIgnore::parse(content).unwrap();
        // Should match both forward and backslash paths
        assert!(ignore.is_ignored("saves\\slot1.sav"));
        assert!(ignore.is_ignored("saves/slot1.sav"));
    }

    #[test]
    fn test_multiple_patterns() {
        let content = r#"
# Ignore logs
*.log
logs/

# Ignore saves
saves/**

# Ignore temp files
*.tmp
"#;
        let ignore = VfsIgnore::parse(content).unwrap();
        assert_eq!(ignore.pattern_count(), 4);

        assert!(ignore.is_ignored("debug.log"));
        assert!(ignore.is_ignored("logs/app.txt"));
        assert!(ignore.is_ignored("saves/slot1.sav"));
        assert!(ignore.is_ignored("cache.tmp"));
        assert!(!ignore.is_ignored("data/textures/hero.pak"));
    }

    #[test]
    fn test_case_insensitive() {
        let content = "Data/Textures/*.DDS";
        let ignore = VfsIgnore::parse(content).unwrap();
        assert!(ignore.is_ignored("data/textures/hero.dds"));
        assert!(ignore.is_ignored("DATA/TEXTURES/HERO.DDS"));
        assert!(ignore.is_ignored("Data/Textures/Hero.DDS"));
    }

    #[test]
    fn test_load_from_file() {
        use std::fs;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let mods_path = temp.path();

        // Create .vfsignore file
        let ignore_content = "*.log\nsaves/\n";
        fs::write(mods_path.join(VFSIGNORE_FILENAME), ignore_content).unwrap();

        let ignore = VfsIgnore::load(mods_path).unwrap();
        assert_eq!(ignore.pattern_count(), 2);
        assert!(ignore.is_ignored("debug.log"));
        assert!(ignore.is_ignored("saves/slot1.sav"));
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let mods_path = temp.path();

        // No .vfsignore file exists
        let ignore = VfsIgnore::load(mods_path).unwrap();
        assert_eq!(ignore.pattern_count(), 0);
        assert!(!ignore.is_ignored("any/path.txt"));
    }
}
