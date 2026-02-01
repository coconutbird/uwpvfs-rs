//! NT API hooking for file system operations
//!
//! This module implements hooks for NtCreateFile and NtOpenFile to redirect
//! file access from the game directory to a mods directory when the modded
//! file exists.

// Allow Windows API naming conventions
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use retour::static_detour;
use thiserror::Error;
use uwpvfs_shared::IpcClient;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::core::{s, w};

/// Error type for hook operations
#[derive(Debug, Error)]
pub enum HookError {
    /// Failed to find ntdll.dll
    #[error("Failed to find ntdll.dll")]
    NtdllNotFound,

    /// Failed to find function address
    #[error("Failed to find function: {0}")]
    FunctionNotFound(&'static str),

    /// Failed to install hook
    #[error("Failed to install hook: {0}")]
    InstallFailed(String),
}

/// Configuration for path redirection
struct VfsConfig {
    /// Original game package path (e.g., C:\Program Files\WindowsApps\...)
    game_path: PathBuf,
    /// Mods directory path
    mods_path: PathBuf,
    /// Whether to log hook calls
    log_traffic: bool,
}

/// Global VFS configuration
static VFS_CONFIG: OnceLock<VfsConfig> = OnceLock::new();

/// Global IPC client for logging from hooks
static IPC_CLIENT: OnceLock<Mutex<IpcClient>> = OnceLock::new();

/// Log a hook call (if logging is enabled)
fn log_hook(func_name: &str, path: &str, redirected: Option<&Path>) {
    let config = match VFS_CONFIG.get() {
        Some(c) if c.log_traffic => c,
        _ => return,
    };
    let _ = config; // silence unused warning

    if let Some(ipc_mutex) = IPC_CLIENT.get() {
        if let Ok(mut ipc) = ipc_mutex.lock() {
            match redirected {
                Some(new_path) => {
                    ipc.info(&format!(
                        "[{}] {} -> {}",
                        func_name,
                        path,
                        new_path.display()
                    ));
                }
                None => {
                    ipc.info(&format!("[{}] {}", func_name, path));
                }
            }
        }
    }
}

// NT API type definitions
type POBJECT_ATTRIBUTES = *mut c_void;
type PIO_STATUS_BLOCK = *mut c_void;
type PLARGE_INTEGER = *mut i64;

/// NtCreateFile function signature
type NtCreateFileFn = unsafe extern "system" fn(
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
type NtOpenFileFn = unsafe extern "system" fn(
    FileHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    IoStatusBlock: PIO_STATUS_BLOCK,
    ShareAccess: u32,
    OpenOptions: u32,
) -> NTSTATUS;

/// LdrLoadDll function signature
type LdrLoadDllFn = unsafe extern "system" fn(
    SearchPath: *const u16,
    DllCharacteristics: *mut u32,
    DllName: *mut UNICODE_STRING,
    BaseAddress: *mut *mut c_void,
) -> NTSTATUS;

// OBJECT_ATTRIBUTES structure for reading the path
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

// Static detours for NT functions
static_detour! {
    static NtCreateFileHook: unsafe extern "system" fn(
        *mut HANDLE, u32, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, u32, u32, u32, u32, *mut c_void, u32
    ) -> NTSTATUS;

    static NtOpenFileHook: unsafe extern "system" fn(
        *mut HANDLE, u32, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, u32, u32
    ) -> NTSTATUS;

    static LdrLoadDllHook: unsafe extern "system" fn(
        *const u16, *mut u32, *mut UNICODE_STRING, *mut *mut c_void
    ) -> NTSTATUS;
}

/// Extract the file path from OBJECT_ATTRIBUTES
unsafe fn get_path_from_object_attributes(obj_attr: POBJECT_ATTRIBUTES) -> Option<String> {
    if obj_attr.is_null() {
        return None;
    }

    // SAFETY: We've checked obj_attr is not null
    let attr = unsafe { &*(obj_attr as *const ObjectAttributes) };
    if attr.object_name.is_null() {
        return None;
    }

    // SAFETY: We've checked object_name is not null
    let unicode_str = unsafe { &*attr.object_name };
    if unicode_str.Buffer.is_null() || unicode_str.Length == 0 {
        return None;
    }

    let len = (unicode_str.Length / 2) as usize;
    // SAFETY: Buffer is valid and Length tells us how many bytes are valid
    let slice = unsafe { std::slice::from_raw_parts(unicode_str.Buffer.as_ptr(), len) };
    Some(String::from_utf16_lossy(slice))
}

/// Check if a path should be redirected and return the redirected path
fn get_redirected_path(original_path: &str) -> Option<PathBuf> {
    let config = VFS_CONFIG.get()?;

    // Convert NT path to DOS path for comparison
    // NT paths look like: \??\C:\... or \Device\HarddiskVolume...\...
    let dos_path = if original_path.starts_with("\\??\\") {
        &original_path[4..]
    } else if original_path.starts_with("\\Device\\") {
        // Can't easily convert device paths, skip them
        return None;
    } else {
        original_path
    };

    // Check if this path is within the game directory
    let game_path_str = config.game_path.to_string_lossy();
    if !dos_path
        .to_lowercase()
        .starts_with(&game_path_str.to_lowercase())
    {
        return None;
    }

    // Get relative path from game directory
    let relative = &dos_path[game_path_str.len()..];
    let relative = relative.trim_start_matches(['\\', '/']);

    // Check if the modded file exists
    let modded_path = config.mods_path.join(relative);
    if modded_path.exists() {
        Some(modded_path)
    } else {
        None
    }
}

/// Create a new UNICODE_STRING pointing to the redirected path
unsafe fn create_redirected_unicode_string(path: &Path) -> (Vec<u16>, UNICODE_STRING) {
    // Convert to NT path format: \??\C:\...
    let path_str = format!("\\??\\{}", path.display());
    let mut wide: Vec<u16> = path_str.encode_utf16().collect();
    wide.push(0); // Null terminator

    let len = ((wide.len() - 1) * 2) as u16;
    let unicode = UNICODE_STRING {
        Length: len,
        MaximumLength: len + 2,
        Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
    };

    (wide, unicode)
}

/// Hooked NtCreateFile implementation
fn nt_create_file_detour(
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
    unsafe {
        // Try to get and redirect the path
        if let Some(original_path) = get_path_from_object_attributes(object_attributes) {
            if let Some(redirected_path) = get_redirected_path(&original_path) {
                // Log the redirection
                log_hook("NtCreateFile", &original_path, Some(&redirected_path));

                // Create new OBJECT_ATTRIBUTES with redirected path
                let (_wide_buf, mut unicode) = create_redirected_unicode_string(&redirected_path);

                let attr = &*(object_attributes as *const ObjectAttributes);
                let mut new_attr = ObjectAttributes {
                    length: attr.length,
                    root_directory: HANDLE::default(), // No root since we use absolute path
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
            } else {
                // Log non-redirected access
                log_hook("NtCreateFile", &original_path, None);
            }
        }

        // No redirection - call original
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

/// Hooked NtOpenFile implementation
fn nt_open_file_detour(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: POBJECT_ATTRIBUTES,
    io_status_block: PIO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    unsafe {
        // Try to get and redirect the path
        if let Some(original_path) = get_path_from_object_attributes(object_attributes) {
            if let Some(redirected_path) = get_redirected_path(&original_path) {
                // Log the redirection
                log_hook("NtOpenFile", &original_path, Some(&redirected_path));

                // Create new OBJECT_ATTRIBUTES with redirected path
                let (_wide_buf, mut unicode) = create_redirected_unicode_string(&redirected_path);

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
            } else {
                // Log non-redirected access
                log_hook("NtOpenFile", &original_path, None);
            }
        }

        // No redirection - call original
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

/// Extract the DLL path from UNICODE_STRING and check for redirection
fn get_redirected_dll_path(dll_name: &UNICODE_STRING) -> Option<PathBuf> {
    let config = VFS_CONFIG.get()?;

    // Extract the DLL path from UNICODE_STRING
    if dll_name.Buffer.is_null() || dll_name.Length == 0 {
        return None;
    }

    let len = (dll_name.Length / 2) as usize;
    let slice = unsafe { std::slice::from_raw_parts(dll_name.Buffer.as_ptr(), len) };
    let dll_path_str = String::from_utf16_lossy(slice);

    // Check if this DLL is in the game directory
    let game_path_str = config.game_path.to_string_lossy();

    // Handle both relative and absolute paths
    let dll_path = Path::new(&dll_path_str);

    // If it's an absolute path in the game directory
    if dll_path_str
        .to_lowercase()
        .starts_with(&game_path_str.to_lowercase())
    {
        let relative = &dll_path_str[game_path_str.len()..];
        let relative = relative.trim_start_matches(['\\', '/']);
        let modded_path = config.mods_path.join(relative);
        if modded_path.exists() {
            return Some(modded_path);
        }
    }

    // If it's a relative path or just a DLL name, check if it exists in mods folder
    if let Some(file_name) = dll_path.file_name() {
        let modded_path = config.mods_path.join(file_name);
        if modded_path.exists() {
            return Some(modded_path);
        }
    }

    None
}

/// Hooked LdrLoadDll implementation
fn ldr_load_dll_detour(
    search_path: *const u16,
    dll_characteristics: *mut u32,
    dll_name: *mut UNICODE_STRING,
    base_address: *mut *mut c_void,
) -> NTSTATUS {
    unsafe {
        if !dll_name.is_null() {
            let dll_name_ref = &*dll_name;

            // Extract DLL name for logging
            let original_dll_name = if !dll_name_ref.Buffer.is_null() && dll_name_ref.Length > 0 {
                let len = (dll_name_ref.Length / 2) as usize;
                let slice = std::slice::from_raw_parts(dll_name_ref.Buffer.as_ptr(), len);
                String::from_utf16_lossy(slice)
            } else {
                String::from("<unknown>")
            };

            if let Some(redirected_path) = get_redirected_dll_path(dll_name_ref) {
                // Log the redirection
                log_hook("LdrLoadDll", &original_dll_name, Some(&redirected_path));

                // Create a new UNICODE_STRING with the redirected path
                let path_str = redirected_path.to_string_lossy();
                let mut wide: Vec<u16> = path_str.encode_utf16().collect();
                wide.push(0);

                let len = ((wide.len() - 1) * 2) as u16;
                let mut new_dll_name = UNICODE_STRING {
                    Length: len,
                    MaximumLength: len + 2,
                    Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
                };

                return LdrLoadDllHook.call(
                    search_path,
                    dll_characteristics,
                    &mut new_dll_name,
                    base_address,
                );
            } else {
                // Log non-redirected DLL load
                log_hook("LdrLoadDll", &original_dll_name, None);
            }
        }

        // No redirection - call original
        LdrLoadDllHook.call(search_path, dll_characteristics, dll_name, base_address)
    }
}

/// Install VFS hooks
/// Returns the number of hooks successfully installed
///
/// If `log_traffic` is true, all file/DLL access will be logged to the console.
/// The `ipc` client is consumed and stored for logging purposes.
pub fn install(
    ipc: IpcClient,
    game_path: &str,
    mods_path: &str,
    log_traffic: bool,
) -> Result<u32, HookError> {
    // Store configuration
    let _ = VFS_CONFIG.set(VfsConfig {
        game_path: PathBuf::from(game_path),
        mods_path: PathBuf::from(mods_path),
        log_traffic,
    });

    // Store IPC client for logging from hooks
    let _ = IPC_CLIENT.set(Mutex::new(ipc));

    // Get IPC client back for initial messages
    let ipc_mutex = IPC_CLIENT.get().unwrap();
    let mut ipc = ipc_mutex.lock().unwrap();

    ipc.info("Installing NT API hooks...");
    if log_traffic {
        ipc.info("Traffic logging enabled");
    }

    unsafe {
        // Get ntdll.dll handle
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).map_err(|_| HookError::NtdllNotFound)?;

        // Get NtCreateFile address
        let nt_create_file = GetProcAddress(ntdll, s!("NtCreateFile"))
            .ok_or(HookError::FunctionNotFound("NtCreateFile"))?;
        let nt_create_file: NtCreateFileFn = std::mem::transmute(nt_create_file);

        // Get NtOpenFile address
        let nt_open_file = GetProcAddress(ntdll, s!("NtOpenFile"))
            .ok_or(HookError::FunctionNotFound("NtOpenFile"))?;
        let nt_open_file: NtOpenFileFn = std::mem::transmute(nt_open_file);

        // Get LdrLoadDll address
        let ldr_load_dll = GetProcAddress(ntdll, s!("LdrLoadDll"))
            .ok_or(HookError::FunctionNotFound("LdrLoadDll"))?;
        let ldr_load_dll: LdrLoadDllFn = std::mem::transmute(ldr_load_dll);

        let mut hooks_installed = 0u32;

        // Install NtCreateFile hook
        NtCreateFileHook
            .initialize(nt_create_file, nt_create_file_detour)
            .map_err(|e| HookError::InstallFailed(format!("NtCreateFile: {}", e)))?;
        NtCreateFileHook
            .enable()
            .map_err(|e| HookError::InstallFailed(format!("NtCreateFile enable: {}", e)))?;
        hooks_installed += 1;
        ipc.info("  ✓ NtCreateFile hooked");

        // Install NtOpenFile hook
        NtOpenFileHook
            .initialize(nt_open_file, nt_open_file_detour)
            .map_err(|e| HookError::InstallFailed(format!("NtOpenFile: {}", e)))?;
        NtOpenFileHook
            .enable()
            .map_err(|e| HookError::InstallFailed(format!("NtOpenFile enable: {}", e)))?;
        hooks_installed += 1;
        ipc.info("  ✓ NtOpenFile hooked");

        // Install LdrLoadDll hook
        LdrLoadDllHook
            .initialize(ldr_load_dll, ldr_load_dll_detour)
            .map_err(|e| HookError::InstallFailed(format!("LdrLoadDll: {}", e)))?;
        LdrLoadDllHook
            .enable()
            .map_err(|e| HookError::InstallFailed(format!("LdrLoadDll enable: {}", e)))?;
        hooks_installed += 1;
        ipc.info("  ✓ LdrLoadDll hooked");

        ipc.success(&format!(
            "VFS hooks installed successfully ({} hooks)",
            hooks_installed
        ));

        Ok(hooks_installed)
    }
}

/// Get access to the IPC client (for use after install)
pub fn get_ipc() -> Option<std::sync::MutexGuard<'static, IpcClient>> {
    IPC_CLIENT.get().and_then(|m| m.lock().ok())
}

/// Clean up hooks when DLL is unloaded
pub fn cleanup() {
    unsafe {
        let _ = NtCreateFileHook.disable();
        let _ = NtOpenFileHook.disable();
        let _ = LdrLoadDllHook.disable();
    }
}
