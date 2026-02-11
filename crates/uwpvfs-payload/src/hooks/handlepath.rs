//! Handle-to-path resolution for NT API hooks
//!
//! This module provides functionality to resolve file/directory handles to their
//! full paths, including conversion from NT device paths to DOS paths.
//!
//! Note: QueryDosDeviceW doesn't work inside the UWP sandbox, so we build the
//! volume mapping by querying a known path (the game directory) using NtQueryObject.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::core::{s, w};

use super::ntapi::{NtQueryObjectFn, OBJECT_NAME_INFORMATION};

// =============================================================================
// Static State
// =============================================================================

/// Cached NtQueryObject function pointer
static NT_QUERY_OBJECT: OnceLock<NtQueryObjectFn> = OnceLock::new();

/// Cached volume device-to-drive mapping (e.g., "\Device\HarddiskVolume3" -> "C:")
static VOLUME_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the handle path resolution system
pub fn init() {
    // Initialize NtQueryObject function pointer
    let _ = NT_QUERY_OBJECT.get_or_init(|| unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok();
        ntdll
            .and_then(|h| GetProcAddress(h, s!("NtQueryObject")))
            .map(|p| std::mem::transmute::<_, NtQueryObjectFn>(p))
            .expect("Failed to get NtQueryObject")
    });

    // Note: VOLUME_MAP is initialized lazily in init_with_game_path
}

/// Initialize volume mapping using the game path
/// This must be called after init() and before any handle resolution
pub fn init_with_game_path(game_path: &Path) {
    let _ = VOLUME_MAP.get_or_init(|| build_volume_map_from_path(game_path));
}

/// Build volume mapping by querying the NT path of a known DOS path
fn build_volume_map_from_path(dos_path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // Extract the drive letter from the path (e.g., "C:" from "C:\Program Files\...")
    let path_str = dos_path.to_string_lossy();
    let drive = if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
        format!("{}:", path_str.chars().next().unwrap().to_ascii_uppercase())
    } else {
        return map; // Not a DOS path with drive letter
    };

    // Open the game directory itself (not the drive root, which may be blocked by sandbox)
    // Add null terminator for Windows API
    let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(path_wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, // Required for directories
            None,
        )
    };

    let handle = match handle {
        Ok(h) => h,
        Err(_) => return map,
    };

    // Query the NT path of this handle
    if let Some(nt_path) = query_handle_nt_path(handle) {
        // nt_path will be like "\Device\HarddiskVolume3\Program Files\WindowsApps\..."
        // dos_path is like "C:\Program Files\WindowsApps\..."
        // We need to extract the device prefix and map it to the drive letter

        // Find where the paths diverge after the device prefix
        // The NT path starts with \Device\HarddiskVolumeN\
        // The DOS path starts with C:\
        // So we need to find the common suffix and extract the prefixes

        let dos_suffix = path_str.get(2..).unwrap_or(""); // Skip "C:" to get "\Program Files\..."
        let dos_suffix_lower = dos_suffix.to_lowercase();
        let nt_path_lower = nt_path.to_lowercase();

        // Find where the NT path ends with the same suffix as the DOS path
        if let Some(pos) = nt_path_lower.find(&dos_suffix_lower) {
            let device_prefix = &nt_path[..pos]; // e.g., "\Device\HarddiskVolume3"
            let device_prefix_lower = device_prefix.to_lowercase();
            map.insert(device_prefix_lower, drive);
        }
    }

    unsafe {
        let _ = CloseHandle(handle);
    }

    map
}

/// Query the NT path from a handle (internal helper)
fn query_handle_nt_path(handle: HANDLE) -> Option<String> {
    let nt_query_object = NT_QUERY_OBJECT.get()?;

    let mut buffer = vec![0u8; 1024];
    let mut return_length: u32 = 0;

    let status: NTSTATUS = unsafe {
        nt_query_object(
            handle,
            OBJECT_NAME_INFORMATION,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut return_length,
        )
    };

    if status.0 != 0 {
        return None;
    }

    let unicode_str = unsafe { &*(buffer.as_ptr() as *const UNICODE_STRING) };
    if unicode_str.Buffer.is_null() || unicode_str.Length == 0 {
        return None;
    }

    let len = (unicode_str.Length / 2) as usize;
    let slice = unsafe { std::slice::from_raw_parts(unicode_str.Buffer.as_ptr(), len) };
    Some(String::from_utf16_lossy(slice))
}

// =============================================================================
// Path Resolution
// =============================================================================

/// Get the full path from a handle using NtQueryObject
///
/// Returns the path in DOS format (e.g., "C:\path\to\file") if successful.
/// Returns None if the handle is invalid or the path cannot be resolved.
pub fn get_path_from_handle(handle: HANDLE) -> Option<String> {
    // Skip invalid handles
    if handle.is_invalid() || handle.0.is_null() {
        return None;
    }

    let nt_query_object = match NT_QUERY_OBJECT.get() {
        Some(f) => f,
        None => {
            // NtQueryObject not initialized - this shouldn't happen
            return None;
        }
    };

    // Buffer for OBJECT_NAME_INFORMATION (UNICODE_STRING + path data)
    // Max path is ~32KB, but most are much shorter
    let mut buffer = vec![0u8; 1024];
    let mut return_length: u32 = 0;

    let status: NTSTATUS = unsafe {
        nt_query_object(
            handle,
            OBJECT_NAME_INFORMATION,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut return_length,
        )
    };

    // STATUS_BUFFER_OVERFLOW or STATUS_INFO_LENGTH_MISMATCH - retry with larger buffer
    if status.0 == 0x80000005_u32 as i32 || status.0 == 0xC0000004_u32 as i32 {
        buffer.resize(return_length as usize, 0);
        let status: NTSTATUS = unsafe {
            nt_query_object(
                handle,
                OBJECT_NAME_INFORMATION,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut return_length,
            )
        };
        if status.0 != 0 {
            return None;
        }
    } else if status.0 != 0 {
        return None;
    }

    // Parse UNICODE_STRING from buffer
    // OBJECT_NAME_INFORMATION is just a UNICODE_STRING
    let unicode_str = unsafe { &*(buffer.as_ptr() as *const UNICODE_STRING) };

    if unicode_str.Buffer.is_null() || unicode_str.Length == 0 {
        return None;
    }

    let len = (unicode_str.Length / 2) as usize;
    let slice = unsafe { std::slice::from_raw_parts(unicode_str.Buffer.as_ptr(), len) };
    let nt_path = String::from_utf16_lossy(slice);

    // Convert NT device path to DOS path
    convert_nt_to_dos_path(&nt_path)
}

/// Convert an NT device path to a DOS path
///
/// Converts paths like "\Device\HarddiskVolume3\path\to\file" to "C:\path\to\file"
fn convert_nt_to_dos_path(nt_path: &str) -> Option<String> {
    // Handle \??\ prefix (already DOS-like)
    if let Some(stripped) = nt_path.strip_prefix("\\??\\") {
        return Some(stripped.to_string());
    }

    // Handle \Device\ paths
    if !nt_path.starts_with("\\Device\\") {
        return Some(nt_path.to_string());
    }

    let volume_map = VOLUME_MAP.get()?;
    let path_lower = nt_path.to_lowercase();

    // Find matching volume
    for (device, drive) in volume_map.iter() {
        if path_lower.starts_with(device) {
            let remainder = &nt_path[device.len()..];
            return Some(format!("{}{}", drive, remainder));
        }
    }

    // No matching volume found
    None
}
