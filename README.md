# VolMenu

A lightweight, menu-driven Python wrapper for [Volatility 3](https://github.com/volatilityfoundation/volatility3) on Windows. VolMenu walks you through configuring `vol.exe`, picking memory images and output folders, choosing a target OS, selecting plugins, and queuing multiple scans to run back-to-back — all from a simple console menu.

## Features

- **Persistent configuration** — stores the path to `vol.exe` and your performance preferences in `HKCU\Software\DFIRVault\VolMenu`, so you only set it up once.
- **Guided `vol.exe` setup** — on first run (or if the configured path is no longer valid), a file picker opens for you to locate `vol.exe`. If you close the picker without selecting a file, VolMenu opens the [Volatility 3 GitHub page](https://github.com/volatilityfoundation/volatility3) so you can download/build it.
- **Automatic symbol table detection** — looks for a `symbols\windows`, `symbols\linux`, or `symbols\mac` folder next to `vol.exe` based on the target OS you select, and automatically passes it to Volatility via `-s`.
- **Performance configuration menu** — toggle parallelism, set worker count, enable verbose output, and control symbol cache behavior.
- **Guided scan setup** — select a memory image, choose an output folder, pick the target OS (Windows, Linux, or Mac), and choose one or more plugins (or run all available plugins for that OS).
- **Scan queue** — configure multiple scans before execution starts; VolMenu runs them sequentially and reports progress for each plugin and each scan.
- **Progress feedback** — live status updates (`RUNNING...`, `DONE [OK]`, etc.) with plugin counters (`[N/total]`) and overall scan counters (`Scan X/Y`) so you always know what's happening.
- **Per-plugin output files** — each plugin's results are saved as a separate `.txt` file in your chosen output directory.

## Requirements

- **Windows** (the tool exits immediately on other platforms — it relies on the Windows Registry and native file dialogs)
- **Python 3.9+** with `tkinter` (included in standard Windows CPython installs)
- **Volatility 3**, either:
  - A standalone `vol.exe` build (e.g. via PyInstaller), or
  - A `vol.py`/`vol` entry point invoked through an equivalent `.exe` wrapper

No third-party Python packages are required — VolMenu only uses the standard library (`winreg`, `tkinter`, `subprocess`, `pathlib`, etc.).

## Installation

1. Make sure Volatility 3 is installed or built (`vol.exe`). See the [Volatility 3 repository](https://github.com/volatilityfoundation/volatility3) for installation instructions.
2. Download `VolMenu.py` from this repository.
3. Run it with Python:

```
python VolMenu.py
```

## First Run

On the first launch, VolMenu checks the registry for a saved `vol.exe` path. If none exists (or the saved path is no longer valid):

1. You'll be prompted to press **Enter** to open a file picker.
2. Browse to and select your `vol.exe` file.
3. The path is saved to `HKCU\Software\DFIRVault\VolMenu` for future runs.

If you **close the file picker without selecting a file**, VolMenu opens the Volatility 3 GitHub page in your default browser and exits, so you can download or build it.

## Main Menu

```
==================================================
 VolMenu - Volatility 3 Wrapper
==================================================
 vol.exe: C:\Tools\volatility3\vol.exe
--------------------------------------------------
 1. New scan
 2. Configure performance settings
 3. Change vol.exe location
 0. Exit
==================================================
```

### 1. New Scan

Starts the guided scan workflow:

1. **Select memory image** — opens a file picker filtered to common memory image extensions (`.raw`, `.mem`, `.dmp`, `.vmem`, `.bin`, `.img`, `.lime`), with an "All files" option.
2. **Select output directory** — opens a folder picker for where plugin results should be saved.
3. **Select target OS** — choose Windows, Linux, or Mac. This determines which symbol directory is used and which plugins are available.
4. **Select plugin(s)** — pick one or more plugins by number (comma-separated), or choose "Run ALL" to run every plugin in the list for that OS.

After configuring a scan, you'll be asked if you want to **queue another scan**. You can repeat this as many times as needed — each scan is added to a queue with its own image, output folder, OS, and plugin selection. Once you decline to add more, VolMenu runs every queued scan in order.

#### Symbol Directory Detection

For each scan, VolMenu looks for a subdirectory next to `vol.exe` matching the selected OS:

```
<vol.exe folder>\symbols\windows
<vol.exe folder>\symbols\linux
<vol.exe folder>\symbols\mac
```

If found, it's passed to Volatility via `-s <path>`. If not found, the scan proceeds without it (Volatility's default symbol resolution still applies).

#### Output

Each plugin produces its own output file named after the plugin, e.g.:

```
windows_pslist_PsList.txt
windows_netscan_NetScan.txt
```

saved into the output directory you selected for that scan.

#### Progress Output

While scans run, VolMenu prints live progress for each plugin and each scan:

```
############################################################
# Scan 1/2: memdump.raw [Windows]
# Using symbols directory: C:\Tools\volatility3\symbols\windows
# Plugins to run: 3
############################################################

[1/3] (Scan 1/2) Running: windows.pslist.PsList
    Command: C:\Tools\volatility3\vol.exe -f memdump.raw windows.pslist.PsList
    Output -> C:\Output\windows_pslist_PsList.txt
    Status: RUNNING... (this may take a while, please wait)
    Status: DONE [OK]  (1/3 complete)
```

### 2. Configure Performance Settings

```
==================================================
 Performance Configuration
==================================================
 1. Parallelism (-p):        OFF
 2. Worker count:            8  (CPUs detected: 8)
 3. Verbose output (-vvv):   OFF
 4. Smart layer caching:     ON
 0. Back to main menu
==================================================
```

- **Parallelism** — when enabled, passes `-p <workers>` to `vol.exe` to enable Volatility 3's parallel processing with the configured worker count.
- **Worker count** — number of workers used when parallelism is enabled.
- **Verbose output** — adds `-vvv` to every plugin run for more detailed logging in the output files.
- **Smart layer caching** — when disabled, adds `--no-symbol-cache` to skip Volatility's symbol cache.

All settings are saved to the registry and applied to every plugin run.

### 3. Change vol.exe Location

Re-opens the file picker so you can point VolMenu at a different `vol.exe` (e.g. after upgrading Volatility 3 or moving your tools directory).

## Configuration Storage

All settings are stored under:

```
HKCU\Software\DFIRVault\VolMenu
```

| Value | Type | Description |
|---|---|---|
| `VolExePath` | `REG_SZ` | Full path to `vol.exe` |
| `ParallelismEnabled` | `REG_DWORD` | `1` if parallelism is enabled |
| `WorkerCount` | `REG_DWORD` | Number of workers for parallelism |
| `VerboseOutput` | `REG_DWORD` | `1` if `-vvv` should be added |
| `SmartCacheEnabled` | `REG_DWORD` | `0` adds `--no-symbol-cache` |

You can safely delete this registry key to reset VolMenu to its initial state.

## Supported Plugins

VolMenu ships with a curated list of commonly used Volatility 3 plugins per OS, including process listing/tree/scanning, network connections, malware-relevant artifacts (`malfind`), registry analysis, file scanning/dumping, loaded modules/drivers, and more. The full list is visible in the plugin selection menu for each OS, and "Run ALL" executes every plugin in that list.

## Disclaimer

VolMenu is a convenience wrapper and does not modify, replace, or bundle Volatility 3 itself. You are responsible for obtaining and complying with the license of Volatility 3 and any symbol tables you use. This tool is intended for legitimate digital forensics, incident response, and educational use.

## License

Specify your preferred license here (e.g. MIT).
