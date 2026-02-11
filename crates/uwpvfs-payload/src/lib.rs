//! UWPVFS DLL - injected into UWP processes to hook file system operations for modding

mod hooks;
mod uwp;
pub mod vfsignore;

use std::ffi::c_void;
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use uwpvfs_shared::IpcClient;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, FreeLibraryAndExitThread};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows::Win32::System::Threading::{CreateThread, GetCurrentProcessId, THREAD_CREATION_FLAGS};

/// Store the module handle so we can unload ourselves
static MODULE_HANDLE: AtomicUsize = AtomicUsize::new(0);

/// DLL entry point
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HMODULE, call_reason: u32, _reserved: *mut c_void) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            // Store module handle for later unloading
            MODULE_HANDLE.store(module.0 as usize, Ordering::SeqCst);

            // Disable thread attach/detach notifications
            unsafe {
                let _ = DisableThreadLibraryCalls(module);
            }

            // Spawn worker thread
            unsafe {
                let _ = CreateThread(
                    None,
                    0,
                    Some(vfs_thread),
                    None,
                    THREAD_CREATION_FLAGS(0),
                    None,
                );
            }
            true
        }
        DLL_PROCESS_DETACH => {
            // Clean up hooks when DLL is unloaded
            hooks::cleanup();
            true
        }
        _ => true,
    }
}

/// Main VFS hooking thread
extern "system" fn vfs_thread(_param: *mut c_void) -> u32 {
    let pid = unsafe { GetCurrentProcessId() };

    // Try to connect to IPC
    let mut ipc = match IpcClient::open(pid) {
        Ok(ipc) => ipc,
        Err(_) => {
            // No IPC available - can't communicate
            unload_self(1);
        }
    };

    // Set up panic hook to send IPC message on crash
    panic::set_hook(Box::new(|panic_info| {
        // Try to send panic info via IPC
        if let Some(mut ipc) = hooks::get_ipc() {
            let location = panic_info
                .location()
                .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
                .unwrap_or_else(|| "<unknown location>".to_string());

            let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "<unknown panic>".to_string()
            };

            ipc.push_packet(uwpvfs_shared::Packet::fatal(&format!(
                "PANIC at {}: {}",
                location, message
            )));
        }
    }));

    // Signal ready
    ipc.push_packet(uwpvfs_shared::Packet::ready());

    // Wait for start signal
    while !ipc.should_start() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Get the mods folder name from shared memory
    let mods_folder = ipc.get_mods_path();

    if mods_folder.is_empty() {
        ipc.push_packet(uwpvfs_shared::Packet::fatal("No mods folder name provided"));
        ipc.set_finished();
        std::thread::sleep(std::time::Duration::from_millis(100));
        unload_self(1);
    }

    // Construct full mods path: TempState\<mods_folder>
    let mods_path = match uwp::get_temp_state_path() {
        Ok(temp_state) => temp_state.join(&mods_folder),
        Err(e) => {
            ipc.push_packet(uwpvfs_shared::Packet::fatal(&format!(
                "Failed to get TempState path: {}",
                e
            )));
            ipc.set_finished();
            std::thread::sleep(std::time::Duration::from_millis(100));
            unload_self(1);
        }
    };

    ipc.info(&format!("Mods directory: {}", mods_path.display()));

    // Get package information
    let package = match uwp::CurrentPackage::current() {
        Ok(p) => p,
        Err(e) => {
            if e.code().0 == 0x80073D54u32 as i32 {
                ipc.push_packet(uwpvfs_shared::Packet::fatal(
                    "This process is not a UWP application",
                ));
            } else {
                ipc.push_packet(uwpvfs_shared::Packet::fatal(&format!(
                    "Failed to get package info: {}",
                    e
                )));
            }
            ipc.set_finished();
            std::thread::sleep(std::time::Duration::from_millis(100));
            unload_self(1);
        }
    };

    ipc.info(&format!("Package: {}", package.full_name));
    ipc.info(&format!("Game path: {}", package.package_path.display()));

    // Check if traffic logging is enabled (via IPC flag)
    let log_traffic = ipc.get_log_traffic();

    // Install the VFS hooks (this consumes the IPC client)

    // Don't unload - keep DLL loaded to maintain hooks
    // The hooks will remain active for the lifetime of the process
    match hooks::install(
        ipc,
        &package.package_path.to_string_lossy(),
        &mods_path.to_string_lossy(),
        log_traffic,
    ) {
        Ok(count) => {
            // Get IPC back from hooks module
            if let Some(mut ipc) = hooks::get_ipc() {
                ipc.set_hooks_installed(count);
                ipc.push_packet(uwpvfs_shared::Packet::hooks_installed(&format!(
                    "{} hooks installed, VFS active",
                    count
                )));
                ipc.set_finished();
            }
            0
        }
        Err(e) => {
            // Get IPC back from hooks module
            if let Some(mut ipc) = hooks::get_ipc() {
                ipc.push_packet(uwpvfs_shared::Packet::fatal(&format!(
                    "Hook installation failed: {}",
                    e
                )));
                ipc.set_finished();
            }
            1
        }
    }
}

/// Unload the DLL and exit the current thread
fn unload_self(exit_code: u32) -> ! {
    unsafe {
        let module = HMODULE(MODULE_HANDLE.load(Ordering::SeqCst) as *mut c_void);
        FreeLibraryAndExitThread(module, exit_code);
    }
}
