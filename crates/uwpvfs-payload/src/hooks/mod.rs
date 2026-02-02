//! NT API hooking for file system operations
//!
//! This module implements hooks for NtCreateFile and NtOpenFile to redirect
//! file access from the game directory to a mods directory when the modded
//! file exists.

mod detours;
mod guard;
pub mod path;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use thiserror::Error;
use uwpvfs_shared::IpcClient;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::core::{s, w};

use detours::*;
use path::VfsConfig;

/// Error type for hook operations
#[derive(Debug, Error)]
pub enum HookError {
    #[error("Failed to find ntdll.dll")]
    NtdllNotFound,

    #[error("Failed to find function: {0}")]
    FunctionNotFound(&'static str),

    #[error("Failed to install hook: {0}")]
    InstallFailed(String),
}

/// Global VFS configuration
static VFS_CONFIG: OnceLock<VfsConfig> = OnceLock::new();

/// Global IPC client for logging from hooks
static IPC_CLIENT: OnceLock<Mutex<IpcClient>> = OnceLock::new();

/// Get the VFS config (for use in detours)
pub(crate) fn get_config() -> Option<&'static VfsConfig> {
    VFS_CONFIG.get()
}

/// Log a redirect (only logs when a file is actually redirected)
pub(crate) fn log_redirect(func_name: &str, original_path: &str, redirected_path: &Path) {
    let config = match VFS_CONFIG.get() {
        Some(c) if c.log_traffic => c,
        _ => return,
    };

    let _ = config;

    let abs_path = path::normalize_to_absolute(original_path);

    if let Some(ipc_mutex) = IPC_CLIENT.get() {
        if let Ok(mut ipc) = ipc_mutex.lock() {
            ipc.info(&format!(
                "[{}] {} -> {}",
                func_name,
                abs_path,
                redirected_path.display()
            ));
        }
    }
}

/// Install VFS hooks
pub fn install(
    ipc: IpcClient,
    game_path: &str,
    mods_path: &str,
    log_traffic: bool,
) -> Result<u32, HookError> {
    // Initialize reentrancy guard
    guard::init();

    // Store configuration
    let _ = VFS_CONFIG.set(VfsConfig {
        game_path: PathBuf::from(game_path),
        mods_path: PathBuf::from(mods_path),
        log_traffic,
    });

    // Store IPC client
    let _ = IPC_CLIENT.set(Mutex::new(ipc));

    let ipc_mutex = IPC_CLIENT.get().unwrap();
    let mut ipc = ipc_mutex.lock().unwrap();

    ipc.info("Installing NT API hooks...");
    if log_traffic {
        ipc.info("Traffic logging enabled");
    }

    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).map_err(|_| HookError::NtdllNotFound)?;

        // Get function addresses
        let nt_create_file = GetProcAddress(ntdll, s!("NtCreateFile"))
            .ok_or(HookError::FunctionNotFound("NtCreateFile"))?;
        let nt_create_file: NtCreateFileFn = std::mem::transmute(nt_create_file);

        let nt_open_file = GetProcAddress(ntdll, s!("NtOpenFile"))
            .ok_or(HookError::FunctionNotFound("NtOpenFile"))?;
        let nt_open_file: NtOpenFileFn = std::mem::transmute(nt_open_file);

        let ldr_load_dll = GetProcAddress(ntdll, s!("LdrLoadDll"))
            .ok_or(HookError::FunctionNotFound("LdrLoadDll"))?;
        let ldr_load_dll: LdrLoadDllFn = std::mem::transmute(ldr_load_dll);

        let mut hooks_installed = 0u32;

        // Install hooks
        NtCreateFileHook
            .initialize(nt_create_file, nt_create_file_detour)
            .map_err(|e| HookError::InstallFailed(format!("NtCreateFile: {}", e)))?;
        NtCreateFileHook
            .enable()
            .map_err(|e| HookError::InstallFailed(format!("NtCreateFile enable: {}", e)))?;
        hooks_installed += 1;
        ipc.info("  ✓ NtCreateFile hooked");

        NtOpenFileHook
            .initialize(nt_open_file, nt_open_file_detour)
            .map_err(|e| HookError::InstallFailed(format!("NtOpenFile: {}", e)))?;
        NtOpenFileHook
            .enable()
            .map_err(|e| HookError::InstallFailed(format!("NtOpenFile enable: {}", e)))?;
        hooks_installed += 1;
        ipc.info("  ✓ NtOpenFile hooked");

        LdrLoadDllHook
            .initialize(ldr_load_dll, ldr_load_dll_detour)
            .map_err(|e| HookError::InstallFailed(format!("LdrLoadDll: {}", e)))?;
        LdrLoadDllHook
            .enable()
            .map_err(|e| HookError::InstallFailed(format!("LdrLoadDll enable: {}", e)))?;
        hooks_installed += 1;
        ipc.info("  ✓ LdrLoadDll hooked");

        // NtQueryAttributesFile - used to check file existence
        let nt_query_attributes_file = GetProcAddress(ntdll, s!("NtQueryAttributesFile"))
            .ok_or(HookError::FunctionNotFound("NtQueryAttributesFile"))?;
        let nt_query_attributes_file: NtQueryAttributesFileFn =
            std::mem::transmute(nt_query_attributes_file);

        NtQueryAttributesFileHook
            .initialize(nt_query_attributes_file, nt_query_attributes_file_detour)
            .map_err(|e| HookError::InstallFailed(format!("NtQueryAttributesFile: {}", e)))?;
        NtQueryAttributesFileHook.enable().map_err(|e| {
            HookError::InstallFailed(format!("NtQueryAttributesFile enable: {}", e))
        })?;
        hooks_installed += 1;
        ipc.info("  ✓ NtQueryAttributesFile hooked");

        // NtQueryFullAttributesFile - extended file existence check
        let nt_query_full_attributes_file = GetProcAddress(ntdll, s!("NtQueryFullAttributesFile"))
            .ok_or(HookError::FunctionNotFound("NtQueryFullAttributesFile"))?;
        let nt_query_full_attributes_file: NtQueryFullAttributesFileFn =
            std::mem::transmute(nt_query_full_attributes_file);

        NtQueryFullAttributesFileHook
            .initialize(
                nt_query_full_attributes_file,
                nt_query_full_attributes_file_detour,
            )
            .map_err(|e| HookError::InstallFailed(format!("NtQueryFullAttributesFile: {}", e)))?;
        NtQueryFullAttributesFileHook.enable().map_err(|e| {
            HookError::InstallFailed(format!("NtQueryFullAttributesFile enable: {}", e))
        })?;
        hooks_installed += 1;
        ipc.info("  ✓ NtQueryFullAttributesFile hooked");

        ipc.success(&format!(
            "VFS hooks installed successfully ({} hooks)",
            hooks_installed
        ));

        Ok(hooks_installed)
    }
}

/// Get access to the IPC client
pub fn get_ipc() -> Option<std::sync::MutexGuard<'static, IpcClient>> {
    IPC_CLIENT.get().and_then(|m| m.lock().ok())
}

/// Clean up hooks
pub fn cleanup() {
    unsafe {
        let _ = NtCreateFileHook.disable();
        let _ = NtOpenFileHook.disable();
        let _ = LdrLoadDllHook.disable();
        let _ = NtQueryAttributesFileHook.disable();
        let _ = NtQueryFullAttributesFileHook.disable();
    }
    guard::cleanup();
}
