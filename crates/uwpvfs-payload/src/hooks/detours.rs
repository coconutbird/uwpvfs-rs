//! Hook detour implementations for NT file APIs
//!
//! This module contains the actual detour functions that intercept NT API calls
//! and redirect file operations to the mods directory when appropriate.

use std::ffi::c_void;
use std::path::PathBuf;

use retour::static_detour;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};

use super::guard::ReentrancyGuard;
use super::ntapi::{
    ObjectAttributes, PIO_STATUS_BLOCK, PLARGE_INTEGER, POBJECT_ATTRIBUTES,
    create_redirected_object_attributes, create_unicode_string, get_path_from_object_attributes,
};
use super::path::{get_redirected_path_ex, should_hide_path};
use super::{get_config, log_hide, log_redirect};

// =============================================================================
// Static Detours
// =============================================================================

static_detour! {
    pub static NtCreateFileHook: unsafe extern "system" fn(
        *mut HANDLE, u32, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, u32, u32, u32, u32, *mut c_void, u32
    ) -> NTSTATUS;

    pub static NtOpenFileHook: unsafe extern "system" fn(
        *mut HANDLE, u32, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, u32, u32
    ) -> NTSTATUS;

    pub static LdrLoadDllHook: unsafe extern "system" fn(
        *const u16, *mut u32, *mut UNICODE_STRING, *mut *mut c_void
    ) -> NTSTATUS;

    pub static NtQueryAttributesFileHook: unsafe extern "system" fn(
        POBJECT_ATTRIBUTES, *mut c_void
    ) -> NTSTATUS;

    pub static NtQueryFullAttributesFileHook: unsafe extern "system" fn(
        POBJECT_ATTRIBUTES, *mut c_void
    ) -> NTSTATUS;

    pub static NtCreateSectionHook: unsafe extern "system" fn(
        *mut HANDLE, u32, POBJECT_ATTRIBUTES, PLARGE_INTEGER, u32, u32, HANDLE
    ) -> NTSTATUS;
}

// =============================================================================
// Constants
// =============================================================================

/// NTSTATUS code for "object name not found" (file/directory doesn't exist)
const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = NTSTATUS(0xC0000034_u32 as i32);

// Access flags indicating write intent
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;

/// Check if the desired_access flags indicate write intent
fn is_write_access(desired_access: u32) -> bool {
    (desired_access & GENERIC_WRITE) != 0
        || (desired_access & FILE_WRITE_DATA) != 0
        || (desired_access & FILE_APPEND_DATA) != 0
}

// =============================================================================
// Redirection Helper
// =============================================================================

/// Attempts to get a redirected path for the given OBJECT_ATTRIBUTES.
/// If `for_write` is true, redirects even if mod file doesn't exist and creates parent dirs.
fn try_get_redirect(
    object_attributes: POBJECT_ATTRIBUTES,
    for_write: bool,
) -> Option<(String, PathBuf)> {
    let config = get_config()?;
    let original_path = unsafe { get_path_from_object_attributes(object_attributes)? };
    let redirected_path = get_redirected_path_ex(config, &original_path, for_write)?;

    // For writes, ensure parent directory exists
    if for_write && let Some(parent) = redirected_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    Some((original_path, redirected_path))
}

/// Checks if the file at the given OBJECT_ATTRIBUTES should be hidden.
/// Returns Some(original_path) if the file should be hidden, None otherwise.
fn try_get_hidden(object_attributes: POBJECT_ATTRIBUTES) -> Option<String> {
    let config = get_config()?;
    let original_path = unsafe { get_path_from_object_attributes(object_attributes)? };
    if should_hide_path(config, &original_path) {
        Some(original_path)
    } else {
        None
    }
}

// =============================================================================
// Detour Implementations
// =============================================================================

/// NtCreateFile detour - intercepts file creation/opening
#[allow(clippy::too_many_arguments)]
pub fn nt_create_file_detour(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: POBJECT_ATTRIBUTES,
    io_status_block: PIO_STATUS_BLOCK,
    allocation_size: PLARGE_INTEGER,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_length: u32,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                NtCreateFileHook.call(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    allocation_size,
                    file_attributes,
                    share_access,
                    create_disposition,
                    create_options,
                    ea_buffer,
                    ea_length,
                )
            };
        }
    };

    // Check if file should be hidden (return "file not found")
    if let Some(original) = try_get_hidden(object_attributes) {
        log_hide("NtCreateFile", &original);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Redirect path (write-aware: creates parent dirs and redirects even if mod file doesn't exist)
    if let Some((original, redirected)) =
        try_get_redirect(object_attributes, is_write_access(desired_access))
    {
        log_redirect("NtCreateFile", &original, &redirected);

        let (_buf, mut unicode) = create_unicode_string(&redirected);
        let attr = unsafe { &*(object_attributes as *const ObjectAttributes) };
        let mut new_attr = create_redirected_object_attributes(attr, &mut unicode);

        return unsafe {
            NtCreateFileHook.call(
                file_handle,
                desired_access,
                &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                io_status_block,
                allocation_size,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
                ea_buffer,
                ea_length,
            )
        };
    }

    unsafe {
        NtCreateFileHook.call(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea_buffer,
            ea_length,
        )
    }
}

/// NtOpenFile detour - intercepts file opening
pub fn nt_open_file_detour(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: POBJECT_ATTRIBUTES,
    io_status_block: PIO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                NtOpenFileHook.call(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    share_access,
                    open_options,
                )
            };
        }
    };

    // Check if file should be hidden (return "file not found")
    if let Some(original) = try_get_hidden(object_attributes) {
        log_hide("NtOpenFile", &original);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Redirect path (write-aware: creates parent dirs and redirects even if mod file doesn't exist)
    if let Some((original, redirected)) =
        try_get_redirect(object_attributes, is_write_access(desired_access))
    {
        log_redirect("NtOpenFile", &original, &redirected);

        let (_buf, mut unicode) = create_unicode_string(&redirected);
        let attr = unsafe { &*(object_attributes as *const ObjectAttributes) };
        let mut new_attr = create_redirected_object_attributes(attr, &mut unicode);

        return unsafe {
            NtOpenFileHook.call(
                file_handle,
                desired_access,
                &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                io_status_block,
                share_access,
                open_options,
            )
        };
    }

    unsafe {
        NtOpenFileHook.call(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            open_options,
        )
    }
}

/// LdrLoadDll detour - DLL redirection disabled (causes crashes due to signature/integrity issues)
pub fn ldr_load_dll_detour(
    search_path: *const u16,
    dll_characteristics: *mut u32,
    dll_name: *mut UNICODE_STRING,
    base_address: *mut *mut c_void,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                LdrLoadDllHook.call(search_path, dll_characteristics, dll_name, base_address)
            };
        }
    };

    // DLL redirection disabled - UWP games have integrity checks that cause crashes
    unsafe { LdrLoadDllHook.call(search_path, dll_characteristics, dll_name, base_address) }
}

/// NtQueryAttributesFile detour - intercepts file existence checks
pub fn nt_query_attributes_file_detour(
    object_attributes: POBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe { NtQueryAttributesFileHook.call(object_attributes, file_information) };
        }
    };

    // Check if file should be hidden (return "file not found")
    if let Some(original) = try_get_hidden(object_attributes) {
        log_hide("NtQueryAttributesFile", &original);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if let Some((original, redirected)) = try_get_redirect(object_attributes, false) {
        log_redirect("NtQueryAttributesFile", &original, &redirected);

        let (_buf, mut unicode) = create_unicode_string(&redirected);
        let attr = unsafe { &*(object_attributes as *const ObjectAttributes) };
        let mut new_attr = create_redirected_object_attributes(attr, &mut unicode);

        return unsafe {
            NtQueryAttributesFileHook.call(
                &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                file_information,
            )
        };
    }

    unsafe { NtQueryAttributesFileHook.call(object_attributes, file_information) }
}

/// NtQueryFullAttributesFile detour - intercepts extended file attribute queries
pub fn nt_query_full_attributes_file_detour(
    object_attributes: POBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                NtQueryFullAttributesFileHook.call(object_attributes, file_information)
            };
        }
    };

    // Check if file should be hidden (return "file not found")
    if let Some(original) = try_get_hidden(object_attributes) {
        log_hide("NtQueryFullAttributesFile", &original);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if let Some((original, redirected)) = try_get_redirect(object_attributes, false) {
        log_redirect("NtQueryFullAttributesFile", &original, &redirected);

        let (_buf, mut unicode) = create_unicode_string(&redirected);
        let attr = unsafe { &*(object_attributes as *const ObjectAttributes) };
        let mut new_attr = create_redirected_object_attributes(attr, &mut unicode);

        return unsafe {
            NtQueryFullAttributesFileHook.call(
                &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                file_information,
            )
        };
    }

    unsafe { NtQueryFullAttributesFileHook.call(object_attributes, file_information) }
}

/// NtCreateSection detour - intercepts memory-mapped file creation
///
/// NtCreateSection can be called with either:
/// - A FileHandle from NtCreateFile/NtOpenFile (already redirected by those hooks)
/// - An ObjectAttributes with a file path (needs redirection here)
#[allow(clippy::too_many_arguments)]
pub fn nt_create_section_detour(
    section_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: POBJECT_ATTRIBUTES,
    maximum_size: PLARGE_INTEGER,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                NtCreateSectionHook.call(
                    section_handle,
                    desired_access,
                    object_attributes,
                    maximum_size,
                    section_page_protection,
                    allocation_attributes,
                    file_handle,
                )
            };
        }
    };

    // Check if file should be hidden (return "file not found")
    // Only check if ObjectAttributes contains a path
    if !object_attributes.is_null()
        && let Some(original) = try_get_hidden(object_attributes)
    {
        log_hide("NtCreateSection", &original);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Only redirect if ObjectAttributes contains a path (FileHandle would be NULL/invalid)
    // If FileHandle is provided, the file was already opened via NtCreateFile/NtOpenFile
    // which would have done the redirection
    if !object_attributes.is_null()
        && let Some((original, redirected)) = try_get_redirect(object_attributes, false)
    {
        log_redirect("NtCreateSection", &original, &redirected);

        let (_buf, mut unicode) = create_unicode_string(&redirected);
        let attr = unsafe { &*(object_attributes as *const ObjectAttributes) };
        let mut new_attr = create_redirected_object_attributes(attr, &mut unicode);

        return unsafe {
            NtCreateSectionHook.call(
                section_handle,
                desired_access,
                &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                maximum_size,
                section_page_protection,
                allocation_attributes,
                file_handle,
            )
        };
    }

    unsafe {
        NtCreateSectionHook.call(
            section_handle,
            desired_access,
            object_attributes,
            maximum_size,
            section_page_protection,
            allocation_attributes,
            file_handle,
        )
    }
}
