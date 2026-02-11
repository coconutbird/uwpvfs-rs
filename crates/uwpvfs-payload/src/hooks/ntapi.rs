//! NT API type definitions and helper structures
//!
//! This module contains the low-level Windows NT API types used for file system hooking.
//! These are internal kernel structures not exposed by the standard Windows API.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};

// =============================================================================
// Pointer Type Aliases
// =============================================================================

/// Pointer to OBJECT_ATTRIBUTES structure
pub type POBJECT_ATTRIBUTES = *mut c_void;

/// Pointer to IO_STATUS_BLOCK structure
pub type PIO_STATUS_BLOCK = *mut c_void;

/// Pointer to LARGE_INTEGER (64-bit integer)
pub type PLARGE_INTEGER = *mut i64;

// =============================================================================
// Function Signatures
// =============================================================================

/// NtCreateFile - Creates or opens a file
pub type NtCreateFileFn = unsafe extern "system" fn(
    FileHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    IoStatusBlock: PIO_STATUS_BLOCK,
    AllocationSize: PLARGE_INTEGER,
    FileAttributes: u32,
    ShareAccess: u32,
    CreateDisposition: u32,
    CreateOptions: u32,
    EaBuffer: *mut c_void,
    EaLength: u32,
) -> NTSTATUS;

/// NtOpenFile - Opens an existing file
pub type NtOpenFileFn = unsafe extern "system" fn(
    FileHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    IoStatusBlock: PIO_STATUS_BLOCK,
    ShareAccess: u32,
    OpenOptions: u32,
) -> NTSTATUS;

/// LdrLoadDll - Loads a DLL into the process
pub type LdrLoadDllFn = unsafe extern "system" fn(
    SearchPath: *const u16,
    DllCharacteristics: *mut u32,
    DllName: *mut UNICODE_STRING,
    BaseAddress: *mut *mut c_void,
) -> NTSTATUS;

/// NtQueryAttributesFile - Queries basic file attributes (existence check)
pub type NtQueryAttributesFileFn = unsafe extern "system" fn(
    ObjectAttributes: POBJECT_ATTRIBUTES,
    FileInformation: *mut c_void,
) -> NTSTATUS;

/// NtQueryFullAttributesFile - Queries extended file attributes
pub type NtQueryFullAttributesFileFn = unsafe extern "system" fn(
    ObjectAttributes: POBJECT_ATTRIBUTES,
    FileInformation: *mut c_void,
) -> NTSTATUS;

/// NtCreateSection - Creates a section object (memory-mapped file)
pub type NtCreateSectionFn = unsafe extern "system" fn(
    SectionHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    MaximumSize: PLARGE_INTEGER,
    SectionPageProtection: u32,
    AllocationAttributes: u32,
    FileHandle: HANDLE,
) -> NTSTATUS;

/// NtQueryDirectoryFile - Enumerates directory contents
pub type NtQueryDirectoryFileFn = unsafe extern "system" fn(
    FileHandle: HANDLE,
    Event: HANDLE,
    ApcRoutine: *mut c_void,
    ApcContext: *mut c_void,
    IoStatusBlock: PIO_STATUS_BLOCK,
    FileInformation: *mut c_void,
    Length: u32,
    FileInformationClass: u32,
    ReturnSingleEntry: u8,
    FileName: *mut UNICODE_STRING,
    RestartScan: u8,
) -> NTSTATUS;

/// NtSetInformationFile - Sets file information (rename, delete, etc.)
pub type NtSetInformationFileFn = unsafe extern "system" fn(
    FileHandle: HANDLE,
    IoStatusBlock: PIO_STATUS_BLOCK,
    FileInformation: *mut c_void,
    Length: u32,
    FileInformationClass: u32,
) -> NTSTATUS;

/// NtDeleteFile - Deletes a file by path
pub type NtDeleteFileFn =
    unsafe extern "system" fn(ObjectAttributes: POBJECT_ATTRIBUTES) -> NTSTATUS;

/// NtQueryObject - Queries object information (used to get path from handle)
pub type NtQueryObjectFn = unsafe extern "system" fn(
    Handle: HANDLE,
    ObjectInformationClass: u32,
    ObjectInformation: *mut c_void,
    ObjectInformationLength: u32,
    ReturnLength: *mut u32,
) -> NTSTATUS;

/// ObjectNameInformation class for NtQueryObject
pub const OBJECT_NAME_INFORMATION: u32 = 1;

// =============================================================================
// Structures
// =============================================================================

/// OBJECT_ATTRIBUTES - Specifies attributes for object creation/opening
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: HANDLE,
    pub object_name: *mut UNICODE_STRING,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

/// FILE_DIRECTORY_INFORMATION - Directory entry returned by NtQueryDirectoryFile
/// FileInformationClass = 1 (FileDirectoryInformation)
#[repr(C)]
pub struct FileDirectoryInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub end_of_file: i64,
    pub allocation_size: i64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    // FileName[1] follows - variable length
}

/// FILE_BOTH_DIR_INFORMATION - Common directory entry format
/// FileInformationClass = 3 (FileBothDirectoryInformation)
#[repr(C)]
pub struct FileBothDirInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub end_of_file: i64,
    pub allocation_size: i64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub ea_size: u32,
    pub short_name_length: u8,
    pub _reserved: u8,
    pub short_name: [u16; 12],
    // FileName[1] follows - variable length
}

// FileInformationClass values we care about
pub const FILE_DIRECTORY_INFORMATION: u32 = 1;
pub const FILE_BOTH_DIR_INFORMATION: u32 = 3;

// FileInformationClass values for NtSetInformationFile
#[allow(dead_code)]
pub const FILE_DISPOSITION_INFORMATION: u32 = 13;
pub const FILE_RENAME_INFORMATION: u32 = 10;

/// FILE_DISPOSITION_INFORMATION structure for delete operations
#[repr(C)]
#[allow(dead_code)]
pub struct FileDispositionInformation {
    pub delete_file: u8, // BOOLEAN - non-zero means delete on close
}

/// FILE_RENAME_INFORMATION structure for rename operations
/// Note: This is a variable-length structure
#[repr(C)]
pub struct FileRenameInformation {
    pub replace_if_exists: u8,  // BOOLEAN
    pub root_directory: HANDLE, // Optional root directory handle
    pub file_name_length: u32,  // Length of FileName in bytes
                                // FileName[1] follows - variable length WCHAR array
}

// NTSTATUS codes
pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_NO_MORE_FILES: i32 = 0x80000006_u32 as i32;

// =============================================================================
// Helper Functions
// =============================================================================

/// Extracts the file path from an OBJECT_ATTRIBUTES structure.
///
/// Handles both absolute paths and relative paths with a root_directory handle.
/// When root_directory is set, resolves the handle to its path and combines
/// with the relative object_name.
///
/// Performs extensive validation to avoid crashes from malformed structures:
/// - Null pointer checks
/// - Alignment validation
/// - Structure length verification
/// - Buffer address sanity checks
///
/// # Safety
/// The caller must ensure `obj_attr` points to readable memory.
pub unsafe fn get_path_from_object_attributes(obj_attr: POBJECT_ATTRIBUTES) -> Option<String> {
    unsafe {
        if obj_attr.is_null() {
            return None;
        }

        // Check pointer alignment (OBJECT_ATTRIBUTES should be 8-byte aligned on x64)
        if !(obj_attr as usize).is_multiple_of(8) {
            return None;
        }

        let attr = &*(obj_attr as *const ObjectAttributes);

        // Validate the structure length field
        if attr.length != std::mem::size_of::<ObjectAttributes>() as u32 {
            return None;
        }

        if attr.object_name.is_null() {
            return None;
        }

        // Check pointer alignment for UNICODE_STRING
        if !(attr.object_name as usize).is_multiple_of(2) {
            return None;
        }

        let unicode_str = &*attr.object_name;
        if unicode_str.Buffer.is_null() || unicode_str.Length == 0 {
            return None;
        }

        // Check buffer pointer - reject obviously invalid addresses
        let buf_addr = unicode_str.Buffer.as_ptr() as usize;
        if buf_addr < 0x10000 || !buf_addr.is_multiple_of(2) {
            return None;
        }

        let len = (unicode_str.Length / 2) as usize;

        // Sanity check: reject suspiciously large lengths (max ~32KB path)
        if len > 16384 {
            return None;
        }

        let slice = std::slice::from_raw_parts(unicode_str.Buffer.as_ptr(), len);
        let s = String::from_utf16_lossy(slice);

        // Trim any embedded or trailing null characters that may be present
        // Some Windows APIs include nulls in the UNICODE_STRING buffer
        let s = s.trim_end_matches('\0').to_string();

        // Also handle embedded nulls by truncating at the first null
        let object_name = if let Some(null_pos) = s.find('\0') {
            s[..null_pos].to_string()
        } else {
            s
        };

        // Check if this is a relative path with a root_directory handle
        if !attr.root_directory.is_invalid() && !attr.root_directory.0.is_null() {
            // Resolve the root directory handle to its path
            if let Some(root_path) = super::handlepath::get_path_from_handle(attr.root_directory) {
                // Combine root path with relative object_name
                let root_path = root_path.trim_end_matches('\\');
                let relative = object_name.trim_start_matches('\\');
                return Some(format!("{}\\{}", root_path, relative));
            }
            // If we can't resolve the handle, fall through to return the object_name as-is
        }

        Some(object_name)
    }
}

/// Creates a UNICODE_STRING from a path for use in redirected calls.
///
/// Returns a tuple of (wide_buffer, UNICODE_STRING) where the buffer must
/// be kept alive for the duration of the UNICODE_STRING's use.
///
/// # Safety
/// The returned UNICODE_STRING contains a raw pointer to the Vec's buffer.
/// The Vec must not be dropped or modified while the UNICODE_STRING is in use.
pub fn create_unicode_string(path: &Path) -> (Vec<u16>, UNICODE_STRING) {
    let path_str = super::path::to_nt_path(path);
    let mut wide: Vec<u16> = path_str.encode_utf16().collect();
    wide.push(0); // Null terminator

    let byte_len = ((wide.len() - 1) * 2) as u16;
    let unicode = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len + 2,
        Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
    };

    (wide, unicode)
}

/// Creates a new OBJECT_ATTRIBUTES with a redirected path.
///
/// # Safety
/// The `unicode` parameter must remain valid for the lifetime of the returned structure.
pub fn create_redirected_object_attributes(
    original: &ObjectAttributes,
    unicode: &mut UNICODE_STRING,
) -> ObjectAttributes {
    ObjectAttributes {
        length: original.length,
        root_directory: HANDLE::default(), // Clear root directory for absolute path
        object_name: unicode as *mut _,
        attributes: original.attributes,
        security_descriptor: original.security_descriptor,
        security_quality_of_service: original.security_quality_of_service,
    }
}
