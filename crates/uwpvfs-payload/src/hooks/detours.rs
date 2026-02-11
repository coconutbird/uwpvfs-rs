//! Hook detour implementations for NT file APIs
//!
//! This module contains the actual detour functions that intercept NT API calls
//! and redirect file operations to the mods directory when appropriate.

use std::ffi::c_void;
use std::path::PathBuf;

use retour::static_detour;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};

use super::dirtrack;
use super::guard::ReentrancyGuard;
use super::ntapi::{
    FILE_BOTH_DIR_INFORMATION, FILE_DIRECTORY_INFORMATION, FILE_RENAME_INFORMATION,
    FileBothDirInformation, FileDirectoryInformation, FileRenameInformation, ObjectAttributes,
    PIO_STATUS_BLOCK, PLARGE_INTEGER, POBJECT_ATTRIBUTES, STATUS_NO_MORE_FILES, STATUS_SUCCESS,
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

    pub static NtQueryDirectoryFileHook: unsafe extern "system" fn(
        HANDLE, HANDLE, *mut c_void, *mut c_void, PIO_STATUS_BLOCK,
        *mut c_void, u32, u32, u8, *mut UNICODE_STRING, u8
    ) -> NTSTATUS;

    pub static NtSetInformationFileHook: unsafe extern "system" fn(
        HANDLE, PIO_STATUS_BLOCK, *mut c_void, u32, u32
    ) -> NTSTATUS;

    pub static NtDeleteFileHook: unsafe extern "system" fn(
        POBJECT_ATTRIBUTES
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

// Create/Open options flag indicating directory
const FILE_DIRECTORY_FILE: u32 = 0x00000001;

// Section page protection flags indicating write intent
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// Check if the desired_access flags indicate write intent
fn is_write_access(desired_access: u32) -> bool {
    (desired_access & GENERIC_WRITE) != 0
        || (desired_access & FILE_WRITE_DATA) != 0
        || (desired_access & FILE_APPEND_DATA) != 0
}

/// Check if section page protection indicates write intent
fn is_write_section(section_page_protection: u32) -> bool {
    (section_page_protection & PAGE_READWRITE) != 0
        || (section_page_protection & PAGE_WRITECOPY) != 0
        || (section_page_protection & PAGE_EXECUTE_READWRITE) != 0
        || (section_page_protection & PAGE_EXECUTE_WRITECOPY) != 0
}

/// Check if options indicate a directory operation
fn is_directory_operation(options: u32) -> bool {
    (options & FILE_DIRECTORY_FILE) != 0
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

    let status = unsafe {
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

    // Register directory handle for enumeration tracking
    if status.0 == STATUS_SUCCESS
        && is_directory_operation(create_options)
        && !file_handle.is_null()
        && let Some(path) = unsafe { get_path_from_object_attributes(object_attributes) }
        && let Some(config) = get_config()
    {
        dirtrack::register_handle(unsafe { *file_handle }, &path, config);
    }

    status
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

    let status = unsafe {
        NtOpenFileHook.call(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            open_options,
        )
    };

    // Register directory handle for enumeration tracking
    if status.0 == STATUS_SUCCESS
        && is_directory_operation(open_options)
        && !file_handle.is_null()
        && let Some(path) = unsafe { get_path_from_object_attributes(object_attributes) }
        && let Some(config) = get_config()
    {
        dirtrack::register_handle(unsafe { *file_handle }, &path, config);
    }

    status
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
    //
    // For write-mode sections, use copy-on-write semantics (for_write: true)
    // This ensures the game file is copied to mods folder before creating the section
    if !object_attributes.is_null() {
        let for_write = is_write_section(section_page_protection);
        if let Some((original, redirected)) = try_get_redirect(object_attributes, for_write) {
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

// =============================================================================
// NtQueryDirectoryFile Detour
// =============================================================================

/// Detour for NtQueryDirectoryFile - directory enumeration
///
/// This hook injects mod files into directory listings when enumerating
/// a game directory that has a corresponding mods directory.
#[allow(clippy::too_many_arguments)]
pub fn nt_query_directory_file_detour(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: PIO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
    return_single_entry: u8,
    file_name: *mut UNICODE_STRING,
    restart_scan: u8,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                NtQueryDirectoryFileHook.call(
                    file_handle,
                    event,
                    apc_routine,
                    apc_context,
                    io_status_block,
                    file_information,
                    length,
                    file_information_class,
                    return_single_entry,
                    file_name,
                    restart_scan,
                )
            };
        }
    };

    // Call original function
    let status = unsafe {
        NtQueryDirectoryFileHook.call(
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            file_information,
            length,
            file_information_class,
            return_single_entry,
            file_name,
            restart_scan,
        )
    };

    // Track returned filenames so we don't inject duplicates
    if status.0 == STATUS_SUCCESS
        && let Some(tracked) = dirtrack::get_tracked(file_handle)
    {
        track_returned_entries(file_information, file_information_class, &tracked);
    }

    // When no more files from original, inject mod files
    if status.0 == STATUS_NO_MORE_FILES
        && let Some(tracked) = dirtrack::get_tracked(file_handle)
        && let Some(mod_file) = tracked.next_pending_mod_file()
        && write_mod_entry(
            file_information,
            length,
            file_information_class,
            &mod_file,
            io_status_block,
        )
    {
        return NTSTATUS(STATUS_SUCCESS);
    }

    status
}

/// Track which filenames were returned in a directory query result
fn track_returned_entries(
    file_information: *mut c_void,
    file_information_class: u32,
    tracked: &dirtrack::TrackedDirGuard,
) {
    if file_information.is_null() {
        return;
    }

    unsafe {
        let mut current = file_information as *const u8;

        loop {
            let filename = match file_information_class {
                FILE_DIRECTORY_INFORMATION => {
                    let entry = &*(current as *const FileDirectoryInformation);
                    let name_ptr =
                        current.add(std::mem::size_of::<FileDirectoryInformation>()) as *const u16;
                    let name_len = (entry.file_name_length / 2) as usize;
                    if name_len > 0 && name_len < 1024 {
                        let slice = std::slice::from_raw_parts(name_ptr, name_len);
                        Some(String::from_utf16_lossy(slice))
                    } else {
                        None
                    }
                }
                FILE_BOTH_DIR_INFORMATION => {
                    let entry = &*(current as *const FileBothDirInformation);
                    let name_ptr =
                        current.add(std::mem::size_of::<FileBothDirInformation>()) as *const u16;
                    let name_len = (entry.file_name_length / 2) as usize;
                    if name_len > 0 && name_len < 1024 {
                        let slice = std::slice::from_raw_parts(name_ptr, name_len);
                        Some(String::from_utf16_lossy(slice))
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(name) = filename {
                tracked.mark_returned(&name);
            }

            // Get next entry offset
            let next_offset = match file_information_class {
                FILE_DIRECTORY_INFORMATION => {
                    (*(current as *const FileDirectoryInformation)).next_entry_offset
                }
                FILE_BOTH_DIR_INFORMATION => {
                    (*(current as *const FileBothDirInformation)).next_entry_offset
                }
                _ => 0,
            };

            if next_offset == 0 {
                break;
            }
            current = current.add(next_offset as usize);
        }
    }
}

/// Write a mod file entry into the directory query buffer
fn write_mod_entry(
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
    mod_file: &dirtrack::ModFileEntry,
    io_status_block: PIO_STATUS_BLOCK,
) -> bool {
    if file_information.is_null() {
        return false;
    }

    let name_wide: Vec<u16> = mod_file.name.encode_utf16().collect();
    let name_bytes = name_wide.len() * 2;

    unsafe {
        match file_information_class {
            FILE_DIRECTORY_INFORMATION => {
                let required_size = std::mem::size_of::<FileDirectoryInformation>() + name_bytes;
                if (length as usize) < required_size {
                    return false;
                }

                let entry = &mut *(file_information as *mut FileDirectoryInformation);
                entry.next_entry_offset = 0;
                entry.file_index = 0;
                entry.creation_time = mod_file.creation_time;
                entry.last_access_time = mod_file.last_write_time;
                entry.last_write_time = mod_file.last_write_time;
                entry.change_time = mod_file.last_write_time;
                entry.end_of_file = mod_file.size as i64;
                entry.allocation_size = mod_file.size as i64;
                entry.file_attributes = mod_file.attributes;
                entry.file_name_length = name_bytes as u32;

                // Copy filename after the struct
                let name_ptr = (file_information as *mut u8)
                    .add(std::mem::size_of::<FileDirectoryInformation>())
                    as *mut u16;
                std::ptr::copy_nonoverlapping(name_wide.as_ptr(), name_ptr, name_wide.len());

                // Set IO_STATUS_BLOCK
                if !io_status_block.is_null() {
                    let status_block = io_status_block as *mut IoStatusBlock;
                    (*status_block).status = 0;
                    (*status_block).information = required_size;
                }

                true
            }
            FILE_BOTH_DIR_INFORMATION => {
                let required_size = std::mem::size_of::<FileBothDirInformation>() + name_bytes;
                if (length as usize) < required_size {
                    return false;
                }

                let entry = &mut *(file_information as *mut FileBothDirInformation);
                entry.next_entry_offset = 0;
                entry.file_index = 0;
                entry.creation_time = mod_file.creation_time;
                entry.last_access_time = mod_file.last_write_time;
                entry.last_write_time = mod_file.last_write_time;
                entry.change_time = mod_file.last_write_time;
                entry.end_of_file = mod_file.size as i64;
                entry.allocation_size = mod_file.size as i64;
                entry.file_attributes = mod_file.attributes;
                entry.file_name_length = name_bytes as u32;
                entry.ea_size = 0;
                entry.short_name_length = 0;
                entry._reserved = 0;
                entry.short_name = [0u16; 12];

                // Copy filename after the struct
                let name_ptr = (file_information as *mut u8)
                    .add(std::mem::size_of::<FileBothDirInformation>())
                    as *mut u16;
                std::ptr::copy_nonoverlapping(name_wide.as_ptr(), name_ptr, name_wide.len());

                // Set IO_STATUS_BLOCK
                if !io_status_block.is_null() {
                    let status_block = io_status_block as *mut IoStatusBlock;
                    (*status_block).status = 0;
                    (*status_block).information = required_size;
                }

                true
            }
            _ => false,
        }
    }
}

/// IO_STATUS_BLOCK structure for directory queries
#[repr(C)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

// =============================================================================
// NtDeleteFile Detour
// =============================================================================

/// Detour for NtDeleteFile - redirects file deletion from game dir to mods dir
pub fn nt_delete_file_detour(object_attributes: POBJECT_ATTRIBUTES) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => return unsafe { NtDeleteFileHook.call(object_attributes) },
    };

    // Check if file should be hidden - if so, pretend it doesn't exist
    if let Some(original) = try_get_hidden(object_attributes) {
        log_hide("NtDeleteFile", &original);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Try to redirect the delete operation to mods folder
    if let Some((original_path, redirected_path)) = try_get_redirect(object_attributes, true) {
        // Only redirect if the mod file exists (we're deleting from mods)
        if redirected_path.exists() {
            log_redirect("NtDeleteFile", &original_path, &redirected_path);

            // Delete the file in the mods folder
            if std::fs::remove_file(&redirected_path).is_ok() {
                return NTSTATUS(STATUS_SUCCESS);
            }
        }
    }

    // Fall through to original for non-redirected paths
    unsafe { NtDeleteFileHook.call(object_attributes) }
}

// =============================================================================
// NtSetInformationFile Detour
// =============================================================================

/// Detour for NtSetInformationFile - handles rename and delete operations
pub fn nt_set_information_file_detour(
    file_handle: HANDLE,
    io_status_block: PIO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                NtSetInformationFileHook.call(
                    file_handle,
                    io_status_block,
                    file_information,
                    length,
                    file_information_class,
                )
            };
        }
    };

    // Handle FileRenameInformation (class 10)
    if file_information_class == FILE_RENAME_INFORMATION
        && !file_information.is_null()
        && let Some(redirected_status) =
            handle_file_rename(file_handle, io_status_block, file_information)
    {
        return redirected_status;
    }

    // For FileDispositionInformation (class 13), we don't need to do anything special
    // The file handle already points to the right location (either game or mod)
    // based on how NtCreateFile/NtOpenFile was redirected

    // Call original for all other cases
    unsafe {
        NtSetInformationFileHook.call(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class,
        )
    }
}

/// Handle file rename operation - redirects destination path if in game directory
fn handle_file_rename(
    file_handle: HANDLE,
    io_status_block: PIO_STATUS_BLOCK,
    file_information: *mut c_void,
) -> Option<NTSTATUS> {
    let config = get_config()?;

    unsafe {
        let rename_info = file_information as *const FileRenameInformation;
        let file_name_length = (*rename_info).file_name_length as usize;

        // Get the filename from the variable-length array after the struct
        let file_name_ptr = (file_information as *const u8)
            .add(std::mem::offset_of!(FileRenameInformation, file_name_length) + 4)
            as *const u16;

        // Convert to string
        let file_name_slice = std::slice::from_raw_parts(file_name_ptr, file_name_length / 2);
        let dest_path = String::from_utf16_lossy(file_name_slice);

        // Check if destination is in game directory and should be redirected
        let redirected_dest = super::path::get_redirected_path_ex(config, &dest_path, true)?;

        // Ensure parent directory exists
        if let Some(parent) = redirected_dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        log_redirect("NtSetInformationFile(Rename)", &dest_path, &redirected_dest);

        // Build new FILE_RENAME_INFORMATION with redirected path
        let new_dest = super::path::to_nt_path(&redirected_dest);
        let new_dest_wide: Vec<u16> = new_dest.encode_utf16().collect();
        let new_name_len = new_dest_wide.len() * 2;

        // Calculate new structure size
        let new_info_size = std::mem::size_of::<FileRenameInformation>() + new_name_len;
        let mut new_info_buffer = vec![0u8; new_info_size];

        // Copy the header (replace_if_exists and root_directory)
        let new_info = new_info_buffer.as_mut_ptr() as *mut FileRenameInformation;
        (*new_info).replace_if_exists = (*rename_info).replace_if_exists;
        (*new_info).root_directory = HANDLE(std::ptr::null_mut()); // Clear root dir since we use absolute path
        (*new_info).file_name_length = new_name_len as u32;

        // Copy the new filename
        let new_name_ptr = (new_info_buffer.as_mut_ptr())
            .add(std::mem::offset_of!(FileRenameInformation, file_name_length) + 4)
            as *mut u16;
        std::ptr::copy_nonoverlapping(new_dest_wide.as_ptr(), new_name_ptr, new_dest_wide.len());

        // Call original with modified info
        let result = NtSetInformationFileHook.call(
            file_handle,
            io_status_block,
            new_info_buffer.as_mut_ptr() as *mut c_void,
            new_info_size as u32,
            FILE_RENAME_INFORMATION,
        );

        Some(result)
    }
}
