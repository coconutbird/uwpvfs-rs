# uwpvfs-rs

[![CI](https://github.com/coconutbird/uwpvfs-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/uwpvfs-rs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/coconutbird/uwpvfs-rs)](https://github.com/coconutbird/uwpvfs-rs/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://github.com/coconutbird/uwpvfs-rs)

A Virtual File System (VFS) tool for enabling modding of sandboxed UWP (Universal Windows Platform) applications, such as Xbox Game Pass games on PC.

## Overview

UWP applications (including Xbox Game Pass games) run in a sandboxed environment that restricts file access, making traditional modding approaches ineffective. **uwpvfs-rs** solves this by injecting a DLL into UWP processes that hooks low-level NT API file operations, redirecting file access to a mods directory.

**Key concept:** The mods folder mirrors the game's directory structure. When the game tries to read a file, the VFS checks if a modded version exists and uses it instead. When the game writes a file, the write goes to the mods folder, preserving the original game files.

## Features

- 🎮 **Launch & Hook** - Launch UWP apps with VFS hooks automatically installed
- 💉 **Process Injection** - Inject into running UWP processes by name or PID
- 📁 **Read Redirection** - Game reads modded files instead of originals
- ✏️ **Write Redirection** - Game writes go to mods folder (originals preserved)
- 📂 **Directory Listing** - Mod files appear when games list folder contents
- 🔄 **Rename/Delete Support** - File operations properly redirected to mods folder
- 🚫 **File Exclusion** - `.vfsignore` to exclude specific files from redirection
- 👻 **File Hiding** - `.vfshide` to make game files appear non-existent
- 📦 **Package Discovery** - List and search installed UWP packages
- 📊 **Traffic Logging** - Optional verbose logging of all file/DLL access
- 🔒 **UWP Compatible** - Proper ACL handling for UWP sandbox access

## Quick Start

1. **Download** the [latest release](https://github.com/coconutbird/uwpvfs-rs/releases/latest) and extract
2. **Find your game's package name**: `uwpvfs --list`
3. **Create your mods folder**: `%LOCALAPPDATA%\Packages\<PackageFamilyName>\AC\TempState\Mods\`
4. **Add mod files** that mirror the game's folder structure
5. **Launch with VFS**: `uwpvfs --package YourGame`

## Installation

### Prerequisites

- Windows 10/11
- Administrator privileges (required for DLL injection)

### Download

Download the zip from [GitHub Releases](https://github.com/coconutbird/uwpvfs-rs/releases/latest) and extract. The zip contains:

- `uwpvfs.exe` - CLI tool
- `uwpvfs_payload.dll` - Injected DLL (must be in same folder as exe)

### Building from Source

```bash
cargo build --release
```

The output binaries will be in `target/release/`.

## Usage

### Launch a UWP app with VFS hooks

```bash
# First, find your game's package name
uwpvfs --list

# Launch by package name (partial match works)
uwpvfs --package HaloWars

# Specify custom mods folder name (default is "Mods")
uwpvfs --package HaloWars --mods MyModPack
```

### Inject into an already-running process

```bash
# By process name
uwpvfs --name HaloWars2_WinAppDX12Final.exe

# By process ID
uwpvfs --pid 12345
```

### Interactive mode

```bash
# Run without arguments to see a list of running UWP processes
uwpvfs
```

### List installed UWP packages

```bash
uwpvfs --list
```

### Enable verbose traffic logging

```bash
# Shows all file access in real-time (useful for debugging)
uwpvfs --package HaloWars --verbose
```

## Mods Folder Structure

Place your mod files in the `TempState\Mods` folder of the UWP app. The folder structure must mirror the game's directory structure.

### Finding the Mods Folder

The mods folder location is:

```
%LOCALAPPDATA%\Packages\<PackageFamilyName>\AC\TempState\Mods\
```

To find your game's `PackageFamilyName`, run `uwpvfs --list` and look for your game.

### Example Structure

If the game has a file at:

```
C:\Program Files\WindowsApps\MyGame_1.0.0.0_x64__abc123\data\textures\player.dds
```

Your mod file should be at:

```
%LOCALAPPDATA%\Packages\MyGame_abc123\TempState\Mods\data\textures\player.dds
```

The VFS automatically redirects the game's file access to your modded version.

## Excluding Files (.vfsignore)

Create a `.vfsignore` file in your mods folder to exclude specific files from VFS redirection. Files matching these patterns will be read from/written to their original locations, bypassing the VFS entirely.

```
%LOCALAPPDATA%\Packages\<PackageFamilyName>\AC\TempState\Mods\.vfsignore
```

### Example .vfsignore

```gitignore
# Let the game write logs to its normal location (not captured in mods)
*.log
logs/

# Exclude cache files that the game regenerates
cache/**
temp/

# Exclude specific files you don't want to mod
data/donotmod.pak
```

### Supported Patterns

| Pattern        | Description                                   |
| -------------- | --------------------------------------------- |
| `*.log`        | Match all `.log` files in any directory       |
| `saves/`       | Match all files in the `saves` directory      |
| `saves/**`     | Match all files in `saves` and subdirectories |
| `data/*.pak`   | Match `.pak` files directly in `data` folder  |
| `cache/temp/*` | Match files directly in `cache/temp`          |

### Use Cases

- **Log files**: Let the game write logs to its normal location
- **Cache files**: Avoid capturing regenerated cache/temp files in mods folder
- **Selective exclusion**: Exclude specific files you don't want the VFS to touch

## Hiding Files (.vfshide)

Create a `.vfshide` file in your mods folder to make game files appear as if they don't exist. When the game tries to access a hidden file, the VFS returns "file not found" - the game thinks the file was never there.

```
%LOCALAPPDATA%\Packages\<PackageFamilyName>\AC\TempState\Mods\.vfshide
```

### Example .vfshide

```gitignore
# Skip intro videos (game will skip them if they "don't exist")
videos/intro.mp4
videos/splash.bik

# Hide all logo/branding files
logos/**

# Hide specific DLC content
dlc/unwanted_pack.pak
```

### How It Works

| File         | In Game | In Mods | In .vfshide | Result                      |
| ------------ | ------- | ------- | ----------- | --------------------------- |
| `intro.mp4`  | ✅      | ❌      | ✅          | **File not found** (hidden) |
| `intro.mp4`  | ✅      | ✅      | ✅          | Uses mod file (replacement) |
| `data.pak`   | ✅      | ✅      | ❌          | Uses mod file               |
| `config.ini` | ✅      | ❌      | ❌          | Uses original game file     |

### Use Cases

- **Skip intro videos**: Many games skip intros if the video file is missing
- **Remove unwanted content**: Hide DLC or content you don't want loaded
- **Disable features**: Hide data files to disable certain game features

> **Tip:** To _replace_ a file, you don't need `.vfshide` - just put your replacement in the mods folder. Use `.vfshide` only when you want to remove a file entirely without providing a replacement.
>
> **Note:** If a file is listed in `.vfshide` but you also have a mod file at that path, the mod file will be used (not hidden).

### Pattern Syntax

`.vfshide` uses the same gitignore-style syntax as `.vfsignore`. See the [Supported Patterns](#supported-patterns) section above.

## Architecture

The project consists of three crates:

| Crate            | Description                                    |
| ---------------- | ---------------------------------------------- |
| `uwpvfs-cli`     | Command-line interface for launching/injecting |
| `uwpvfs-payload` | DLL injected into target processes             |
| `uwpvfs-shared`  | Shared IPC protocol and message types          |

### How it works

1. **CLI** creates shared memory with proper ACLs for UWP sandbox access
2. **CLI** injects the payload DLL into the target process
3. **DLL** hooks low-level Windows NT API functions (see table below)
4. When the game accesses a file, the hook checks if a mod version exists
5. **Reads**: If mod file exists, redirect to it; otherwise use original
6. **Writes**: Always redirect to mods folder (copy original first if needed)
7. **IPC** communicates status and logs between CLI and DLL

### Copy-on-Write

When a game opens a file for writing:

- If the mod file already exists → write to it
- If only the original exists → copy original to mods folder first, then write
- If neither exists → create new file in mods folder

This preserves original game files while capturing all modifications.

### Hooked NT API Functions

| Function                    | Purpose                                        |
| --------------------------- | ---------------------------------------------- |
| `NtCreateFile`              | File creation and opening                      |
| `NtOpenFile`                | File opening                                   |
| `NtQueryAttributesFile`     | File existence checks                          |
| `NtQueryFullAttributesFile` | Extended file attribute queries                |
| `NtCreateSection`           | Memory-mapped file access                      |
| `NtQueryDirectoryFile`      | Directory listing (shows mod files in results) |
| `NtSetInformationFile`      | File rename operations                         |
| `NtDeleteFile`              | File deletion                                  |
| `LdrLoadDll`                | DLL loading (logging only)                     |

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
