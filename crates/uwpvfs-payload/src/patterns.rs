//! Shared pattern matching utilities for VFS configuration files
//!
//! Provides gitignore-style pattern matching used by both `.vfsignore` and `.vfshide`.
//!
//! # Syntax
//!
//! - Lines starting with `#` are comments
//! - Empty lines are ignored
//! - Patterns use glob syntax (`*`, `**`, `?`)
//! - Patterns are matched against the relative path from the game/mods folder

use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs;
use std::path::Path;

/// Parsed pattern set for matching file paths
#[derive(Debug)]
pub struct PatternSet {
    /// Compiled glob patterns
    patterns: GlobSet,
    /// Number of patterns loaded (for logging)
    pattern_count: usize,
}

impl Default for PatternSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl PatternSet {
    /// Create an empty pattern set (matches nothing)
    pub fn empty() -> Self {
        Self {
            patterns: GlobSet::empty(),
            pattern_count: 0,
        }
    }

    /// Load and parse a pattern file from the given directory
    pub fn load(dir_path: &Path, filename: &str) -> Result<Self, PatternError> {
        let file_path = dir_path.join(filename);

        if !file_path.exists() {
            return Ok(Self::empty());
        }

        let content = fs::read_to_string(&file_path)
            .map_err(|e| PatternError::ReadError(file_path.clone(), e))?;

        Self::parse(&content)
    }

    /// Parse pattern content from a string
    pub fn parse(content: &str) -> Result<Self, PatternError> {
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
                PatternError::InvalidPattern(line_num + 1, line.to_string(), e.to_string())
            })?;

            builder.add(glob);
            pattern_count += 1;
        }

        let patterns = builder
            .build()
            .map_err(|e| PatternError::BuildError(e.to_string()))?;

        Ok(Self {
            patterns,
            pattern_count,
        })
    }

    /// Check if a relative path matches any pattern
    pub fn is_match(&self, relative_path: &str) -> bool {
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

/// Errors that can occur when loading/parsing pattern files
#[derive(Debug)]
pub enum PatternError {
    /// Failed to read the pattern file
    ReadError(std::path::PathBuf, std::io::Error),
    /// Invalid glob pattern
    InvalidPattern(usize, String, String),
    /// Failed to build the glob set
    BuildError(String),
}

impl std::fmt::Display for PatternError {
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

impl std::error::Error for PatternError {}
