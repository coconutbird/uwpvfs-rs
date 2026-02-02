# uwpvfs-rs

A Virtual File System (VFS) tool for enabling modding of sandboxed UWP (Universal Windows Platform) applications.

## Overview

UWP applications run in a sandboxed environment that restricts file access, making traditional modding approaches ineffective. **uwpvfs-rs** solves this by injecting a DLL into UWP processes that hooks low-level NT API file operations, redirecting file access to a mods directory when modded files exist.

## Features

- 🎮 **Launch & Hook** - Launch UWP apps with VFS hooks automatically installed
- 💉 **Process Injection** - Inject into running UWP processes by name or PID
- 📁 **File Redirection** - Transparently redirect file access to mods folder
- 📦 **Package Discovery** - List and search installed UWP packages
- 📊 **Traffic Logging** - Optional verbose logging of all file/DLL access
- 🔒 **UWP Compatible** - Proper ACL handling for UWP sandbox access

## Installation

### Prerequisites

- Windows 10/11 with UWP support
- Rust toolchain (2024 edition)

### Building

```bash
cargo build --release
```

The output binaries will be in `target/release/`:

- `uwpvfs.exe` - CLI tool
- `uwpvfs_payload.dll` - Injected DLL

## Usage

### Launch a UWP app with VFS hooks

```bash
# Launch by package name
uwpvfs --package Microsoft.HoganThreshold

# Specify custom mods folder name
uwpvfs --package Microsoft.HoganThreshold --mods MyModPack
```

### Inject into a running process

```bash
# By process name
uwpvfs --name HaloWars2_WinAppDX12Final.exe

# By process ID
uwpvfs --pid 12345
```

### Interactive mode

```bash
# Lists all UWP processes and lets you select one
uwpvfs
```

### List installed UWP packages

```bash
uwpvfs --list
```

### Enable verbose traffic logging

```bash
uwpvfs --package Microsoft.HoganThreshold --verbose
```

## Mods Folder Location

Place your mod files in the `TempState` folder of the UWP app:

```
%LOCALAPPDATA%\Packages\<PackageFamilyName>\TempState\Mods\
```

The VFS will redirect file access from the game directory to this mods folder when a matching file exists.

## Architecture

The project consists of three crates:

| Crate            | Description                                    |
| ---------------- | ---------------------------------------------- |
| `uwpvfs-cli`     | Command-line interface for launching/injecting |
| `uwpvfs-payload` | DLL injected into target processes             |
| `uwpvfs-shared`  | Shared IPC protocol and message types          |

### How it works

1. **CLI** creates shared memory with proper ACLs for UWP access
2. **CLI** injects the payload DLL into the target process
3. **DLL** hooks NT API functions (`NtCreateFile`, `NtOpenFile`, etc.)
4. **DLL** checks if requested files exist in the mods directory
5. If mod file exists, the path is redirected; otherwise, original path is used
6. **IPC** communicates status and logs between CLI and DLL

## CLI Options

| Option                | Description                                         |
| --------------------- | --------------------------------------------------- |
| `-n, --name <NAME>`   | Process name to inject into                         |
| `-p, --pid <PID>`     | Process ID to inject into                           |
| `-l, --list`          | List all installed UWP packages                     |
| `--package <NAME>`    | Package name to launch with VFS hooks               |
| `-m, --mods <FOLDER>` | Mods folder name inside TempState (default: "Mods") |
| `-v, --verbose`       | Enable verbose traffic logging                      |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This tool is intended for legitimate modding purposes. Use responsibly and in accordance with the terms of service of the applications you modify.
