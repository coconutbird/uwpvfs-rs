//! Hook detour implementations for NT file APIs

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::path::Path;

use retour::static_detour;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};

use super::guard::ReentrancyGuard;
use super::path::{get_redirected_path, to_nt_path};
use super::{get_config, log_redirect};

// NT API type definitions
pub type POBJECT_ATTRIBUTES = *mut c_void;
pub type PIO_STATUS_BLOCK = *mut c_void;
pub type PLARGE_INTEGER = *mut i64;

/// NtCreateFile function signature
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

/// NtOpenFile function signature
pub type NtOpenFileFn = unsafe extern "system" fn(
    FileHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    IoStatusBlock: PIO_STATUS_BLOCK,
    ShareAccess: u32,
    OpenOptions: u32,
) -> NTSTATUS;

/// LdrLoadDll function signature
pub type LdrLoadDllFn = unsafe extern "system" fn(
    SearchPath: *const u16,
    DllCharacteristics: *mut u32,
    DllName: *mut UNICODE_STRING,
    BaseAddress: *mut *mut c_void,
) -> NTSTATUS;

/// NtQueryAttributesFile function signature
/// Used to check file existence/attributes without opening
pub type NtQueryAttributesFileFn = unsafe extern "system" fn(
    ObjectAttributes: POBJECT_ATTRIBUTES,
    FileInformation: *mut c_void, // FILE_BASIC_INFORMATION
) -> NTSTATUS;

/// NtQueryFullAttributesFile function signature
/// Extended version that returns more file information
pub type NtQueryFullAttributesFileFn = unsafe extern "system" fn(
    ObjectAttributes: POBJECT_ATTRIBUTES,
    FileInformation: *mut c_void, // FILE_NETWORK_OPEN_INFORMATION
) -> NTSTATUS;

// OBJECT_ATTRIBUTES structure
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: HANDLE,
    pub object_name: *mut UNICODE_STRING,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

// Static detours
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
}

/// Extract the file path from OBJECT_ATTRIBUTES with validation
///
/// # Safety
/// The caller must ensure `obj_attr` points to a valid OBJECT_ATTRIBUTES structure.
pub unsafe fn get_path_from_object_attributes(obj_attr: POBJECT_ATTRIBUTES) -> Option<String> {
    unsafe {
        if obj_attr.is_null() {
            return None;
        }

        // Check pointer alignment (OBJECT_ATTRIBUTES should be 8-byte aligned on x64)
        if (obj_attr as usize) % 8 != 0 {
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
        if (attr.object_name as usize) % 2 != 0 {
            return None;
        }

        let unicode_str = &*attr.object_name;
        if unicode_str.Buffer.is_null() || unicode_str.Length == 0 {
            return None;
        }

        // Check buffer pointer - reject obviously invalid addresses
        let buf_addr = unicode_str.Buffer.as_ptr() as usize;
        if buf_addr < 0x10000 || buf_addr % 2 != 0 {
            return None;
        }

        let len = (unicode_str.Length / 2) as usize;

        // Sanity check: reject suspiciously large lengths
        if len > 16384 {
            return None;
        }

        let slice = std::slice::from_raw_parts(unicode_str.Buffer.as_ptr(), len);
        Some(String::from_utf16_lossy(slice))
    }
}

/// Create a new UNICODE_STRING pointing to the redirected path
pub unsafe fn create_redirected_unicode_string(path: &Path) -> (Vec<u16>, UNICODE_STRING) {
    let path_str = to_nt_path(path);
    let mut wide: Vec<u16> = path_str.encode_utf16().collect();
    wide.push(0);

    let len = ((wide.len() - 1) * 2) as u16;
    let unicode = UNICODE_STRING {
        Length: len,
        MaximumLength: len + 2,
        Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
    };

    (wide, unicode)
}

/// NtCreateFile detour
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
    // Reentrancy guard
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

    unsafe {
        if let Some(config) = get_config() {
            if let Some(original_path) = get_path_from_object_attributes(object_attributes) {
                if let Some(redirected_path) = get_redirected_path(config, &original_path) {
                    log_redirect("NtCreateFile", &original_path, &redirected_path);

                    let (_wide_buf, mut unicode) =
                        create_redirected_unicode_string(&redirected_path);
                    let attr = &*(object_attributes as *const ObjectAttributes);
                    let mut new_attr = ObjectAttributes {
                        length: attr.length,
                        root_directory: HANDLE::default(),
                        object_name: &mut unicode as *mut _,
                        attributes: attr.attributes,
                        security_descriptor: attr.security_descriptor,
                        security_quality_of_service: attr.security_quality_of_service,
                    };

                    return NtCreateFileHook.call(
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
                    );
                }
            }
        }

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

/// NtOpenFile detour
pub fn nt_open_file_detour(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: POBJECT_ATTRIBUTES,
    io_status_block: PIO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    // Reentrancy guard
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

    unsafe {
        if let Some(config) = get_config() {
            if let Some(original_path) = get_path_from_object_attributes(object_attributes) {
                if let Some(redirected_path) = get_redirected_path(config, &original_path) {
                    log_redirect("NtOpenFile", &original_path, &redirected_path);

                    let (_wide_buf, mut unicode) =
                        create_redirected_unicode_string(&redirected_path);
                    let attr = &*(object_attributes as *const ObjectAttributes);
                    let mut new_attr = ObjectAttributes {
                        length: attr.length,
                        root_directory: HANDLE::default(),
                        object_name: &mut unicode as *mut _,
                        attributes: attr.attributes,
                        security_descriptor: attr.security_descriptor,
                        security_quality_of_service: attr.security_quality_of_service,
                    };

                    return NtOpenFileHook.call(
                        file_handle,
                        desired_access,
                        &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                        io_status_block,
                        share_access,
                        open_options,
                    );
                }
            }
        }

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

/// LdrLoadDll detour (currently disabled)
pub fn ldr_load_dll_detour(
    search_path: *const u16,
    dll_characteristics: *mut u32,
    dll_name: *mut UNICODE_STRING,
    base_address: *mut *mut c_void,
) -> NTSTATUS {
    // Reentrancy guard
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                LdrLoadDllHook.call(search_path, dll_characteristics, dll_name, base_address)
            };
        }
    };

    // DLL redirection is currently disabled
    unsafe { LdrLoadDllHook.call(search_path, dll_characteristics, dll_name, base_address) }
}

/// NtQueryAttributesFile detour
/// Games use this to check if a file exists before opening it
pub fn nt_query_attributes_file_detour(
    object_attributes: POBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    // Reentrancy guard
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe { NtQueryAttributesFileHook.call(object_attributes, file_information) };
        }
    };

    unsafe {
        if let Some(config) = get_config() {
            if let Some(original_path) = get_path_from_object_attributes(object_attributes) {
                if let Some(redirected_path) = get_redirected_path(config, &original_path) {
                    log_redirect("NtQueryAttributesFile", &original_path, &redirected_path);

                    let (_wide_buf, mut unicode) =
                        create_redirected_unicode_string(&redirected_path);
                    let attr = &*(object_attributes as *const ObjectAttributes);
                    let mut new_attr = ObjectAttributes {
                        length: attr.length,
                        root_directory: HANDLE::default(),
                        object_name: &mut unicode as *mut _,
                        attributes: attr.attributes,
                        security_descriptor: attr.security_descriptor,
                        security_quality_of_service: attr.security_quality_of_service,
                    };

                    return NtQueryAttributesFileHook.call(
                        &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                        file_information,
                    );
                }
            }
        }

        NtQueryAttributesFileHook.call(object_attributes, file_information)
    }
}

/// NtQueryFullAttributesFile detour
/// Extended version that returns more file information
pub fn nt_query_full_attributes_file_detour(
    object_attributes: POBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    // Reentrancy guard
    let _guard = match ReentrancyGuard::try_enter() {
        Some(g) => g,
        None => {
            return unsafe {
                NtQueryFullAttributesFileHook.call(object_attributes, file_information)
            };
        }
    };

    unsafe {
        if let Some(config) = get_config() {
            if let Some(original_path) = get_path_from_object_attributes(object_attributes) {
                if let Some(redirected_path) = get_redirected_path(config, &original_path) {
                    log_redirect(
                        "NtQueryFullAttributesFile",
                        &original_path,
                        &redirected_path,
                    );

                    let (_wide_buf, mut unicode) =
                        create_redirected_unicode_string(&redirected_path);
                    let attr = &*(object_attributes as *const ObjectAttributes);
                    let mut new_attr = ObjectAttributes {
                        length: attr.length,
                        root_directory: HANDLE::default(),
                        object_name: &mut unicode as *mut _,
                        attributes: attr.attributes,
                        security_descriptor: attr.security_descriptor,
                        security_quality_of_service: attr.security_quality_of_service,
                    };

                    return NtQueryFullAttributesFileHook.call(
                        &mut new_attr as *mut _ as POBJECT_ATTRIBUTES,
                        file_information,
                    );
                }
            }
        }

        NtQueryFullAttributesFileHook.call(object_attributes, file_information)
    }
}
