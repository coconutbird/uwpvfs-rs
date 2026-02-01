//! UWPVFS CLI - injects VFS hooking DLL into UWP processes for mod support

mod inject;
mod package;
mod process;

use clap::Parser;
use colored::Colorize;
use std::io::{self, Write};
use std::path::PathBuf;
use uwpvfs_shared::{IpcHost, LogLevel, Packet, PacketId};

#[derive(Parser)]
#[command(name = "uwpvfs")]
#[command(about = "UWP Virtual File System - enables modding of sandboxed UWP applications")]
#[command(version)]
struct Args {
    /// Process name to inject into (e.g., HaloWars2_WinAppDX12Final.exe)
    #[arg(short, long)]
    name: Option<String>,

    /// Process ID to inject into
    #[arg(short, long)]
    pid: Option<u32>,

    /// List all installed UWP packages
    #[arg(short, long)]
    list: bool,

    /// Package name to launch with VFS hooks (e.g., Microsoft.HoganThreshold)
    #[arg(long = "package")]
    package: Option<String>,

    /// Mods folder name inside TempState (e.g., "Mods", "MyModPack")
    #[arg(short, long, default_value = "Mods")]
    mods: String,

    /// Enable verbose traffic logging (log all file/DLL access)
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    print_banner();

    // Handle --list flag
    if args.list {
        list_packages_command();
        return;
    }

    // Mods folder name (just the folder name, not full path)
    let mods_folder = &args.mods;
    let verbose = args.verbose;

    // Handle --package flag (launch with VFS hooks)
    if let Some(ref pkg_name) = args.package {
        launch_and_hook(pkg_name, mods_folder, verbose);
        return;
    }

    // Get DLL path (same directory as exe)
    let dll_path = match get_dll_path() {
        Some(p) => p,
        None => return,
    };

    // Determine target process
    let target = if args.pid.is_some() || args.name.is_some() {
        match find_process(args.pid, args.name.as_deref()) {
            Some(p) => p,
            None => {
                if let Some(pid) = args.pid {
                    eprintln!("{} No UWP process found with PID: {}", "[ERROR]".red(), pid);
                } else if let Some(ref name) = args.name {
                    eprintln!(
                        "{} No UWP process found matching: {}",
                        "[ERROR]".red(),
                        name
                    );
                }
                return;
            }
        }
    } else {
        // Interactive mode
        match select_process_interactive() {
            Some(p) => p,
            None => return,
        }
    };

    println!(
        "\n{} Selected: {} (PID: {})",
        "[INFO]".blue(),
        target.name,
        target.pid
    );

    inject_and_hook(target.pid, &dll_path, mods_folder, verbose);
}

fn print_banner() {
    println!();
    println!("{}", "UWPVFS".cyan().bold());
    println!("{}", "UWP Virtual File System for modding".white());
    println!();
}

/// Get and validate the DLL path
/// Returns None if DLL doesn't exist
fn get_dll_path() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().unwrap_or_default();
    let dll_path = exe_path
        .parent()
        .unwrap_or(&exe_path)
        .join("uwpvfs_payload.dll");

    if dll_path.exists() {
        Some(dll_path)
    } else {
        eprintln!(
            "{} DLL not found at: {}",
            "[ERROR]".red(),
            dll_path.display()
        );
        eprintln!("Make sure uwpvfs_payload.dll is in the same directory as this executable.");
        None
    }
}

fn list_packages_command() {
    println!("{} Listing installed UWP packages...\n", "[INFO]".blue());

    match package::list_packages() {
        Ok(mut packages) => {
            if packages.is_empty() {
                println!("{} No UWP packages found.", "[WARN]".yellow());
            } else {
                // Sort alphabetically by display name (case-insensitive)
                packages.sort_by(|a, b| {
                    a.display_name
                        .to_lowercase()
                        .cmp(&b.display_name.to_lowercase())
                });

                println!(
                    "{:<35} {}",
                    "Display Name".cyan().bold(),
                    "Package Name".cyan().bold(),
                );

                println!("{}", "-".repeat(80));

                for pkg in packages {
                    println!("{:<35} {}", pkg.display_name, pkg.name);
                }
            }
        }
        Err(e) => {
            eprintln!("{} Failed to list packages: {}", "[ERROR]".red(), e);
        }
    }
}

fn launch_and_hook(pkg_name: &str, mods_path: &str, verbose: bool) {
    // Find the package
    println!("{} Looking for package: {}", "[INFO]".blue(), pkg_name);

    let pkg = match package::find_package(pkg_name) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!(
                "{} No package found matching: {}",
                "[ERROR]".red(),
                pkg_name
            );
            return;
        }
        Err(e) => {
            eprintln!("{} Failed to find package: {}", "[ERROR]".red(), e);
            return;
        }
    };

    println!(
        "{} Found: {} ({})",
        "[OK]".green(),
        pkg.name,
        pkg.family_name
    );

    println!("{} Launching application...", "[INFO]".blue());

    // Launch the app
    let pid = match package::launch_package(&pkg) {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("{} Failed to launch package: {}", "[ERROR]".red(), e);
            return;
        }
    };

    println!("{} Launched with PID: {}", "[OK]".green(), pid);

    // Immediately suspend the process before it can do anything
    println!("{} Suspending process...", "[INFO]".blue());
    if let Err(e) = inject::suspend_process(pid) {
        eprintln!("{} Failed to suspend process: {}", "[ERROR]".red(), e);
        return;
    }
    println!("{} Process suspended", "[OK]".green());

    // Now inject and install VFS hooks while suspended
    let dll_path = match get_dll_path() {
        Some(p) => p,
        None => return,
    };

    inject_and_hook(pid, &dll_path, mods_path, verbose);
}

fn inject_and_hook(pid: u32, dll_path: &std::path::Path, mods_path: &str, verbose: bool) {
    // Set up IPC
    println!("{} Setting up IPC...", "[INFO]".blue());
    let mut ipc = match IpcHost::create(pid) {
        Ok(ipc) => ipc,
        Err(e) => {
            eprintln!("{} Failed to create IPC: {}", "[ERROR]".red(), e);
            return;
        }
    };

    // Set mods path and logging flag in shared memory before injection
    ipc.set_mods_path(mods_path);
    ipc.set_log_traffic(verbose);

    if verbose {
        println!("{} Traffic logging enabled", "[INFO]".blue());
    }

    // Inject DLL
    println!("{} Injecting VFS DLL...", "[INFO]".blue());
    let process = match inject::inject_dll(pid, dll_path) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("{} Injection failed: {}", "[ERROR]".red(), e);
            return;
        }
    };

    println!(
        "{} DLL injected, waiting for ready signal...",
        "[OK]".green()
    );

    // Wait for ready signal
    let mut ready = false;
    for _ in 0..500 {
        if !process.is_alive() {
            eprintln!(
                "{} Target process crashed during initialization",
                "[ERROR]".red()
            );
            return;
        }
        if let Some(pkt) = ipc.try_read()
            && pkt.id() == PacketId::Ready
        {
            ready = true;
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    if !ready {
        eprintln!("{} Timeout waiting for DLL ready signal", "[ERROR]".red());
        return;
    }

    // Start VFS hooks and run message loop
    println!("{} Installing VFS hooks...\n", "[INFO]".blue());

    ipc.start_hooks();

    run_message_loop(&mut ipc, &process);

    println!();
}

fn find_process(pid: Option<u32>, name: Option<&str>) -> Option<process::ProcessInfo> {
    let processes = process::list_uwp_processes().ok()?;

    if let Some(pid) = pid {
        processes.into_iter().find(|p| p.pid == pid)
    } else if let Some(name) = name {
        let name_lower = name.to_lowercase();
        processes
            .into_iter()
            .find(|p| p.name.to_lowercase().contains(&name_lower))
    } else {
        None
    }
}

fn select_process_interactive() -> Option<process::ProcessInfo> {
    println!("{} Scanning for UWP processes...", "[INFO]".blue());
    let processes = match process::list_uwp_processes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Failed to list processes: {}", "[ERROR]".red(), e);
            return None;
        }
    };

    if processes.is_empty() {
        println!("{} No UWP processes found.", "[WARN]".yellow());

        return None;
    }

    // Display process list
    println!(
        "\n{} Found {} UWP processes:\n",
        "[OK]".green(),
        processes.len()
    );
    for (i, proc) in processes.iter().enumerate() {
        println!("  [{}] {} (PID: {})", i + 1, proc.name.cyan(), proc.pid);
    }

    // Get user selection
    print!("\nEnter process number (or 0 to exit): ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return None;
    }

    let selection: usize = match input.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("{} Invalid input", "[ERROR]".red());
            return None;
        }
    };

    if selection == 0 || selection > processes.len() {
        return None;
    }

    Some(processes.into_iter().nth(selection - 1).unwrap())
}

/// Main message loop - displays packets and waits for hooks to be installed
fn run_message_loop(ipc: &mut IpcHost, process: &inject::ProcessHandle) {
    loop {
        // Check if target process crashed
        if !process.is_alive() {
            eprintln!(
                "\n{} Target process crashed or was terminated",
                "[ERROR]".red()
            );
            return;
        }

        // Process packets
        while let Some(pkt) = ipc.try_read() {
            display_packet(&pkt);
            match pkt.id() {
                PacketId::HooksInstalled => {
                    // VFS hooks successfully installed - done!
                    return;
                }
                PacketId::Fatal => {
                    return;
                }
                _ => {}
            }
        }

        // Acknowledge sync
        ipc.check_and_ack_sync();

        if ipc.is_finished() {
            // Drain remaining packets
            while let Some(pkt) = ipc.try_read() {
                display_packet(&pkt);
            }
            return;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Display a packet from the DLL
fn display_packet(pkt: &Packet) {
    match pkt.id() {
        PacketId::Log => match pkt.log_level() {
            Some(LogLevel::Info) => println!("{} {}", "[INFO]".blue(), pkt.message()),
            Some(LogLevel::Success) => println!("{} {}", "[OK]".green(), pkt.message()),
            Some(LogLevel::Warning) => println!("{} {}", "[WARN]".yellow(), pkt.message()),
            Some(LogLevel::Error) => println!("{} {}", "[ERROR]".red(), pkt.message()),
            None => {}
        },
        PacketId::HooksInstalled => {
            println!("{} {}", "[VFS]".green().bold(), pkt.message());
        }
        PacketId::Fatal => {
            println!("{} {}", "[FATAL]".red().bold(), pkt.message());
        }
        _ => {}
    }
}
