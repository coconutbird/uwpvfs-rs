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

use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs;
use std::path::Path;

/// Name of the ignore file
pub const VFSIGNORE_FILENAME: &str = ".vfsignore";

/// Parsed vfsignore rules for pattern matching
#[derive(Debug)]
pub struct VfsIgnore {
    /// Compiled glob patterns for exclusion
    patterns: GlobSet,
    /// Number of patterns loaded (for logging)
    pattern_count: usize,
}

impl Default for VfsIgnore {
    fn default() -> Self {
        Self::empty()
    }
}

impl VfsIgnore {
    /// Create an empty ignore set (matches nothing)
    pub fn empty() -> Self {
        Self {
            patterns: GlobSet::empty(),
            pattern_count: 0,
        }
    }

    /// Load and parse a .vfsignore file from the given mods directory
    pub fn load(mods_path: &Path) -> Result<Self, VfsIgnoreError> {
        let ignore_path = mods_path.join(VFSIGNORE_FILENAME);

        if !ignore_path.exists() {
            return Ok(Self::empty());
        }

        let content = fs::read_to_string(&ignore_path)
            .map_err(|e| VfsIgnoreError::ReadError(ignore_path.clone(), e))?;

        Self::parse(&content)
    }

    /// Parse vfsignore content from a string
    pub fn parse(content: &str) -> Result<Self, VfsIgnoreError> {
        let mut builder = GlobSetBuilder::new();
        let mut pattern_count = 0;

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Normalize pattern: convert forward slashes to work on Windows
            let pattern = normalize_pattern(line);

            // Compile the glob pattern
            let glob = Glob::new(&pattern).map_err(|e| {
                VfsIgnoreError::InvalidPattern(line_num + 1, line.to_string(), e.to_string())
            })?;

            builder.add(glob);
            pattern_count += 1;
        }

        let patterns = builder
            .build()
            .map_err(|e| VfsIgnoreError::BuildError(e.to_string()))?;

        Ok(Self {
            patterns,
            pattern_count,
        })
    }

    /// Check if a relative path should be ignored (excluded from redirection)
    pub fn is_ignored(&self, relative_path: &str) -> bool {
        if self.pattern_count == 0 {
            return false;
        }

        // Normalize the path for matching (use forward slashes for consistency)
        let normalized = relative_path.replace('\\', "/").to_lowercase();
        self.patterns.is_match(&normalized)
    }

    /// Get the number of patterns loaded
    pub fn pattern_count(&self) -> usize {
        self.pattern_count
    }
}

/// Normalize a pattern for cross-platform matching
fn normalize_pattern(pattern: &str) -> String {
    // Convert backslashes to forward slashes
    let mut normalized = pattern.replace('\\', "/");

    // Convert to lowercase for case-insensitive matching (Windows paths)
    normalized = normalized.to_lowercase();

    // If pattern ends with /, treat it as a directory match (add **)
    if normalized.ends_with('/') {
        normalized.push_str("**");
    }

    normalized
}

/// Errors that can occur when loading/parsing vfsignore
#[derive(Debug)]
pub enum VfsIgnoreError {
    /// Failed to read the ignore file
    ReadError(std::path::PathBuf, std::io::Error),
    /// Invalid glob pattern
    InvalidPattern(usize, String, String),
    /// Failed to build the glob set
    BuildError(String),
}

impl std::fmt::Display for VfsIgnoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadError(path, e) => write!(f, "Failed to read {}: {}", path.display(), e),
            Self::InvalidPattern(line, pattern, e) => {
                write!(f, "Invalid pattern on line {}: '{}' - {}", line, pattern, e)
            }
            Self::BuildError(e) => write!(f, "Failed to build pattern matcher: {}", e),
        }
    }
}

impl std::error::Error for VfsIgnoreError {}

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

