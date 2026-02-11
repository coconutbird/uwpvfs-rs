//! VFS hide file parsing and matching
//!
//! Provides gitignore-style pattern matching for hiding game files from access.
//! When a file matches a `.vfshide` pattern, the VFS returns "file not found"
//! making it appear as if the file doesn't exist.
//!
//! The `.vfshide` file should be placed in the mods folder root.
//!
//! # Syntax
//!
//! - Lines starting with `#` are comments
//! - Empty lines are ignored
//! - Patterns use glob syntax (`*`, `**`, `?`)
//! - Patterns are matched against the relative path from the game folder
//!
//! # Example `.vfshide`
//!
//! ```text
//! # Hide intro videos
//! videos/intro.mp4
//! videos/splash.bik
//!
//! # Hide all logo files
//! logos/**
//!
//! # Hide specific DLC content
//! dlc/unwanted_pack.pak
//! ```

use crate::patterns::{PatternError, PatternSet};
use std::path::Path;

/// Name of the hide file
pub const VFSHIDE_FILENAME: &str = ".vfshide";

/// Parsed vfshide rules for pattern matching
#[derive(Debug)]
pub struct VfsHide(PatternSet);

impl Default for VfsHide {
    fn default() -> Self {
        Self::empty()
    }
}

impl VfsHide {
    /// Create an empty hide set (matches nothing)
    pub fn empty() -> Self {
        Self(PatternSet::empty())
    }

    /// Load and parse a .vfshide file from the given mods directory
    pub fn load(mods_path: &Path) -> Result<Self, PatternError> {
        Ok(Self(PatternSet::load(mods_path, VFSHIDE_FILENAME)?))
    }

    /// Parse vfshide content from a string
    pub fn parse(content: &str) -> Result<Self, PatternError> {
        Ok(Self(PatternSet::parse(content)?))
    }

    /// Check if a relative path should be hidden (return file not found)
    pub fn is_hidden(&self, relative_path: &str) -> bool {
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
    fn test_empty_hide() {
        let hide = VfsHide::empty();
        assert_eq!(hide.pattern_count(), 0);
        assert!(!hide.is_hidden("any/path.txt"));
    }

    #[test]
    fn test_parse_empty_content() {
        let hide = VfsHide::parse("").unwrap();
        assert_eq!(hide.pattern_count(), 0);
    }

    #[test]
    fn test_parse_simple_pattern() {
        let content = "videos/intro.mp4";
        let hide = VfsHide::parse(content).unwrap();
        assert_eq!(hide.pattern_count(), 1);
        assert!(hide.is_hidden("videos/intro.mp4"));
        assert!(hide.is_hidden("Videos/Intro.MP4")); // case insensitive
        assert!(!hide.is_hidden("videos/outro.mp4"));
    }

    #[test]
    fn test_parse_directory_pattern() {
        let content = "logos/";
        let hide = VfsHide::parse(content).unwrap();
        assert!(hide.is_hidden("logos/company.png"));
        assert!(hide.is_hidden("logos/splash/main.png"));
        assert!(!hide.is_hidden("textures/logo.png"));
    }

    #[test]
    fn test_parse_glob_star_pattern() {
        let content = "dlc/unwanted/**";
        let hide = VfsHide::parse(content).unwrap();
        assert!(hide.is_hidden("dlc/unwanted/pack1.pak"));
        assert!(hide.is_hidden("dlc/unwanted/extra/pack2.pak"));
        assert!(!hide.is_hidden("dlc/wanted/pack.pak"));
    }

    #[test]
    fn test_wildcard_pattern() {
        let content = "*.bik";
        let hide = VfsHide::parse(content).unwrap();
        assert!(hide.is_hidden("intro.bik"));
        assert!(hide.is_hidden("splash.BIK"));
        assert!(!hide.is_hidden("intro.mp4"));
    }

    #[test]
    fn test_multiple_patterns() {
        let content = r#"
# Hide intro videos
videos/intro.mp4
videos/splash.bik

# Hide all logos
logos/**
"#;
        let hide = VfsHide::parse(content).unwrap();
        assert_eq!(hide.pattern_count(), 3);

        assert!(hide.is_hidden("videos/intro.mp4"));
        assert!(hide.is_hidden("videos/splash.bik"));
        assert!(hide.is_hidden("logos/main.png"));
        assert!(!hide.is_hidden("data/textures/hero.pak"));
    }

    #[test]
    fn test_load_from_file() {
        use std::fs;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let mods_path = temp.path();

        // Create .vfshide file
        let hide_content = "videos/intro.mp4\nlogos/\n";
        fs::write(mods_path.join(VFSHIDE_FILENAME), hide_content).unwrap();

        let hide = VfsHide::load(mods_path).unwrap();
        assert_eq!(hide.pattern_count(), 2);
        assert!(hide.is_hidden("videos/intro.mp4"));
        assert!(hide.is_hidden("logos/splash.png"));
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let mods_path = temp.path();

        // No .vfshide file exists
        let hide = VfsHide::load(mods_path).unwrap();
        assert_eq!(hide.pattern_count(), 0);
        assert!(!hide.is_hidden("any/path.txt"));
    }
}
