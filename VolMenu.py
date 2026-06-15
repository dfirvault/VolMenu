"""
VolMenu - A Windows-only interactive menu wrapper for Volatility 3.

Features:
- Persists configuration (vol.exe path, performance settings) in
  HKCU\\Software\\DFIRVault\\VolMenu
- File-picker driven setup for vol.exe, with fallback to the
  Volatility 3 GitHub page if the picker is cancelled
- Performance configuration menu (parallelism / workers / verbosity)
- New scan workflow: select memory image, output directory, target OS,
  then plugin(s) to run (or "Run all")
- Scan queue: after configuring a scan, the user can queue another one;
  all queued scans run sequentially at the end
- **NEW:** After each scan, an HTML report is generated containing all
  plugin outputs in a single file with a built‑in search and navigation.

Requires: Windows, Python 3.9+, Volatility 3 (vol.exe via PyInstaller build
or a vol.py entry point), tkinter (bundled with standard CPython on Windows).
"""

import os
import re
import sys
import subprocess
import threading
import time
import webbrowser
import html
from pathlib import Path

# ---------------------------------------------------------------------------
# Platform guard
# ---------------------------------------------------------------------------
if os.name != "nt":
    print("VolMenu is Windows-only. Exiting.")
    sys.exit(1)

import winreg  # noqa: E402  (Windows-only import, after platform guard)
import msvcrt  # noqa: E402  (Windows-only import, for checkbox menu input)

try:
    import tkinter as tk
    from tkinter import filedialog
except ImportError:
    print("tkinter is required for the file picker but is not available.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Cancellation handling
# ---------------------------------------------------------------------------
class Cancelled(Exception):
    """Raised to unwind a scan-configuration step back to the main menu."""
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REG_ROOT = winreg.HKEY_CURRENT_USER
REG_PATH = r"Software\DFIRVault\VolMenu"

VOL_EXE_VALUE = "VolExePath"
PERF_PARALLELISM_VALUE = "ParallelismMode"
PERF_VERBOSE_VALUE = "VerboseOutput"
PERF_SMARTCACHE_VALUE = "SmartCacheEnabled"

VOLATILITY3_URL = "https://github.com/volatilityfoundation/volatility3"

# ---------------------------------------------------------------------------
# Plugin catalogue (Volatility 3 - common plugins per OS)
# Trimmed to the most widely used plugins; "Run all" iterates this list.
# ---------------------------------------------------------------------------
PLUGINS = {
    "windows": [
        "windows.info.Info",
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.psscan.PsScan",
        "windows.dlllist.DllList",
        "windows.handles.Handles",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
        "windows.netstat.NetStat",
        "windows.malfind.Malfind",
        "windows.modules.Modules",
        "windows.modscan.ModScan",
        "windows.driverscan.DriverScan",
        "windows.svcscan.SvcScan",
        "windows.registry.hivelist.HiveList",
        "windows.registry.printkey.PrintKey",
        "windows.filescan.FileScan",
        "windows.dumpfiles.DumpFiles",
        "windows.envars.Envars",
        "windows.getsids.GetSIDs",
        "windows.privileges.Privs",
        "windows.sessions.Sessions",
        "windows.mutantscan.MutantScan",
        "windows.symlinkscan.SymlinkScan",
        "windows.vadinfo.VadInfo",
        "windows.memmap.Memmap",
        "windows.ssdt.SSDT",
    ],
    "linux": [
        "linux.bash.Bash",
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.psaux.PsAux",
        "linux.lsmod.Lsmod",
        "linux.lsof.Lsof",
        "linux.malfind.Malfind",
        "linux.netstat.Netstat",
        "linux.proc.Maps",
        "linux.elfs.Elfs",
        "linux.check_afinfo.Check_afinfo",
        "linux.check_creds.Check_creds",
        "linux.check_idt.Check_idt",
        "linux.check_syscall.Check_syscall",
        "linux.mountinfo.MountInfo",
        "linux.tty_check.tty_check",
    ],
    "mac": [
        "mac.pslist.PsList",
        "mac.pstree.PsTree",
        "mac.psaux.Psaux",
        "mac.lsmod.Lsmod",
        "mac.lsof.Lsof",
        "mac.netstat.Netstat",
        "mac.malfind.Malfind",
        "mac.bash.Bash",
        "mac.check_syscall.Check_syscall",
        "mac.ifconfig.Ifconfig",
        "mac.mount.Mount",
        "mac.proc_maps.Maps",
    ],
}

OS_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "mac": "Mac",
}


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def _open_or_create_key():
    return winreg.CreateKeyEx(REG_ROOT, REG_PATH, 0, winreg.KEY_ALL_ACCESS)


def reg_get(name, default=None):
    try:
        with winreg.OpenKey(REG_ROOT, REG_PATH, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return default


def reg_set(name, value):
    with _open_or_create_key() as key:
        if isinstance(value, bool):
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
        elif isinstance(value, int):
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        else:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))


def reg_get_bool(name, default=False):
    val = reg_get(name, None)
    if val is None:
        return default
    return bool(val)


def reg_get_int(name, default=0):
    val = reg_get(name, None)
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# File / folder picker helpers (tkinter, hidden root window)
# ---------------------------------------------------------------------------
def _tk_root():
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    return root


def pick_file(title, filetypes=(("All files", "*.*"),), initialdir=None):
    root = _tk_root()
    try:
        path = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes,
            initialdir=initialdir,
        )
    finally:
        root.destroy()
    return path or None


def pick_directory(title, initialdir=None):
    root = _tk_root()
    try:
        path = filedialog.askdirectory(title=title, initialdir=initialdir)
    finally:
        root.destroy()
    return path or None


# ---------------------------------------------------------------------------
# Checkbox-style multi-select console menu
# ---------------------------------------------------------------------------
_KEY_UP = {b"H", b"\x48"}
_KEY_DOWN = {b"P", b"\x50"}
_KEY_SPACE = b" "
_KEY_ENTER = {b"\r", b"\n"}
_KEY_ESC = b"\x1b"


def checkbox_menu(title, items, extra_options=None):
    """Interactive checkbox-style multi-select menu.

    Arrow keys (or w/s) move the cursor, Space toggles the highlighted
    item, 'a' selects/deselects all, Enter confirms the selection, and
    Esc / 'c' cancels (raises Cancelled).

    items: list of display strings.
    extra_options: optional list of (label, key) tuples shown below the
        items but not included in the checkbox set (e.g. "Run ALL").
        Selecting one of these via Enter on that row returns the special
        marker string for that option's key instead of a list of indices.

    Returns: list of selected indices into `items` (0-based), OR
             the `key` string of a chosen extra_option.
    Raises:  Cancelled if the user presses Esc or 'c'.
    """
    extra_options = extra_options or []
    selected = [False] * len(items)
    cursor = 0
    total_rows = len(items) + len(extra_options)

    def render():
        os.system("cls")
        print(title)
        print("-" * len(title) if title else "")
        for idx, label in enumerate(items):
            box = "[x]" if selected[idx] else "[ ]"
            pointer = ">" if idx == cursor else " "
            print(f" {pointer} {box} {idx + 1:2d}. {label}")
        for offset, (label, _key) in enumerate(extra_options):
            row = len(items) + offset
            pointer = ">" if row == cursor else " "
            print(f" {pointer}     {label}")
        print()
        print("Space: toggle   Enter: confirm   A: select/deselect all   "
              "Up/Down or W/S: move   Esc or C: cancel (back to main menu)")

    render()
    while True:
        key = msvcrt.getch()

        if key == _KEY_ESC or key.lower() == b"c":
            raise Cancelled()

        if key in (b"\x00", b"\xe0"):
            # Extended key (arrow keys) - read the follow-up byte
            key2 = msvcrt.getch()
            if key2 in _KEY_UP:
                cursor = (cursor - 1) % total_rows
            elif key2 in _KEY_DOWN:
                cursor = (cursor + 1) % total_rows
            render()
            continue

        if key.lower() == b"w":
            cursor = (cursor - 1) % total_rows
            render()
            continue

        if key.lower() == b"s":
            cursor = (cursor + 1) % total_rows
            render()
            continue

        if key == _KEY_SPACE:
            if cursor < len(items):
                selected[cursor] = not selected[cursor]
            render()
            continue

        if key.lower() == b"a":
            new_state = not all(selected)
            selected = [new_state] * len(items)
            render()
            continue

        if key in _KEY_ENTER:
            if cursor >= len(items):
                # An "extra option" row was confirmed
                _, extra_key = extra_options[cursor - len(items)]
                return extra_key

            chosen = [i for i, s in enumerate(selected) if s]
            if not chosen:
                # Nothing checked - treat Enter on an item row as a quick
                # single-select for convenience.
                chosen = [cursor]
            return chosen


# ---------------------------------------------------------------------------
# vol.exe setup / validation
# ---------------------------------------------------------------------------
def prompt_for_vol_exe():
    """Show a file picker for vol.exe. If cancelled, open the volatility3
    GitHub page and exit. Used for initial setup / when no valid path is
    configured."""
    print("\nVolatility 3 executable (vol.exe) not configured or not found.")
    print("A file picker will open - please select your vol.exe file.")
    input("Press Enter to continue...")

    path = pick_file(
        title="Select vol.exe (Volatility 3)",
        filetypes=(("vol.exe", "vol.exe"), ("Executable files", "*.exe"), ("All files", "*.*")),
    )

    if not path:
        print("\nNo file selected.")
        print(f"Opening Volatility 3 releases page: {VOLATILITY3_URL}")
        try:
            webbrowser.open(VOLATILITY3_URL)
        except Exception:
            pass
        print("Please download/build Volatility 3, then re-run VolMenu.")
        sys.exit(0)

    if not os.path.isfile(path):
        print("Selected path does not exist. Exiting.")
        sys.exit(1)

    path = os.path.normpath(path)
    reg_set(VOL_EXE_VALUE, path)
    print(f"Saved vol.exe path: {path}")
    return path


def change_vol_exe(current_vol_exe):
    """Show a file picker to change the configured vol.exe path. If the
    picker is cancelled, keep the current path and return to the main menu
    without exiting."""
    print("\nSelect a new vol.exe location (or close the picker to keep "
          "the current configuration).")
    input("Press Enter to continue...")

    path = pick_file(
        title="Select vol.exe (Volatility 3)",
        filetypes=(("vol.exe", "vol.exe"), ("Executable files", "*.exe"), ("All files", "*.*")),
    )

    if not path:
        print("\nNo file selected. Keeping the current vol.exe path.")
        return current_vol_exe

    if not os.path.isfile(path):
        print("Selected path does not exist. Keeping the current vol.exe path.")
        return current_vol_exe

    path = os.path.normpath(path)
    reg_set(VOL_EXE_VALUE, path)
    print(f"Saved vol.exe path: {path}")
    return path


def ensure_vol_exe():
    """Validate the stored vol.exe path on every launch. Re-prompt if
    missing or invalid."""
    path = reg_get(VOL_EXE_VALUE, None)
    if path:
        path = os.path.normpath(path)
    if path and os.path.isfile(path):
        return path
    if path:
        print(f"\nConfigured vol.exe path no longer exists: {path}")
    return prompt_for_vol_exe()


# ---------------------------------------------------------------------------
# Performance configuration menu
# ---------------------------------------------------------------------------
PARALLELISM_MODES = ["off", "processes", "threads"]


def show_performance_menu():
    while True:
        mode_idx = reg_get_int(PERF_PARALLELISM_VALUE, 0)
        if mode_idx < 0 or mode_idx >= len(PARALLELISM_MODES):
            mode_idx = 0
        mode = PARALLELISM_MODES[mode_idx]
        verbose = reg_get_bool(PERF_VERBOSE_VALUE, False)
        smartcache = reg_get_bool(PERF_SMARTCACHE_VALUE, True)

        print("\n" + "=" * 50)
        print(" Performance Configuration")
        print("=" * 50)
        print(f" 1. Parallelism (--parallelism): {mode}")
        print(f" 2. Verbose output (-vvv):       {'ON' if verbose else 'OFF'}")
        print(f" 3. Smart layer caching:         {'ON' if smartcache else 'OFF'}")
        print(" 0. Back to main menu")
        print("=" * 50)

        choice = input("Select an option: ").strip()

        if choice == "1":
            next_idx = (mode_idx + 1) % len(PARALLELISM_MODES)
            reg_set(PERF_PARALLELISM_VALUE, next_idx)
            print(f"Parallelism set to: {PARALLELISM_MODES[next_idx]}")
        elif choice == "2":
            reg_set(PERF_VERBOSE_VALUE, not verbose)
            print(f"Verbose output {'enabled' if not verbose else 'disabled'}.")
        elif choice == "3":
            reg_set(PERF_SMARTCACHE_VALUE, not smartcache)
            print(f"Smart layer caching {'enabled' if not smartcache else 'disabled'}.")
        elif choice == "0":
            return
        else:
            print("Invalid option.")


def build_perf_args():
    """Translate stored performance settings into vol.exe CLI args."""
    args = []

    mode_idx = reg_get_int(PERF_PARALLELISM_VALUE, 0)
    if 0 <= mode_idx < len(PARALLELISM_MODES):
        mode = PARALLELISM_MODES[mode_idx]
        if mode != "off":
            # --parallelism takes a mode: 'processes' or 'threads'
            args.extend(["--parallelism", mode])

    if reg_get_bool(PERF_VERBOSE_VALUE, False):
        args.append("-vvv")
    if not reg_get_bool(PERF_SMARTCACHE_VALUE, True):
        args.append("--no-symbol-cache")
    return args


# ---------------------------------------------------------------------------
# Symbol directory detection
# ---------------------------------------------------------------------------
def find_symbols_dir(vol_exe, target_os):
    """Look for a symbols\\<os> subdirectory next to vol.exe and return its
    path if found, else None."""
    vol_dir = Path(vol_exe).resolve().parent
    candidate = vol_dir / "symbols" / target_os
    if candidate.is_dir():
        return str(candidate)
    return None


# ---------------------------------------------------------------------------
# HTML Report Generation (NEW)
# ---------------------------------------------------------------------------
def generate_html_report(output_dir, job_info):
    """
    Creates an HTML dashboard in output_dir that contains all plugin result
    .txt files found in that directory. Provides a search box and a
    collapsible table of contents.
    """
    output_path = Path(output_dir)
    txt_files = sorted(output_path.glob("*.txt"))
    if not txt_files:
        print(f"    No .txt result files found in {output_dir} – skipping HTML report.")
        return

    # Prepare data for HTML
    sections = []
    for txt_file in txt_files:
        # Generate a nice title from the filename
        stem = txt_file.stem  # e.g. windows_info_Info
        title = stem.replace("_", " ").title()
        # Optionally map back to original plugin name (if needed)
        # Read file content and escape HTML
        try:
            content = txt_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            content = f"Error reading file: {e}"
        sections.append({
            "id": stem,
            "title": title,
            "filename": txt_file.name,
            "content": content
        })

    # Build HTML
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Volatility Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f0f2f5;
            color: #1e2a3a;
            line-height: 1.5;
        }
        .container {
            display: flex;
            min-height: 100vh;
        }
        /* Sidebar (Table of Contents) */
        .toc {
            width: 280px;
            background: #fff;
            border-right: 1px solid #ddd;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            box-shadow: 2px 0 5px rgba(0,0,0,0.05);
            z-index: 10;
        }
        .toc h2 {
            font-size: 1.2rem;
            padding: 1rem;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
            color: #0b5ed7;
        }
        .toc ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .toc li {
            border-bottom: 1px solid #f0f0f0;
        }
        .toc a {
            display: block;
            padding: 0.6rem 1rem;
            text-decoration: none;
            color: #2c3e50;
            font-size: 0.9rem;
            transition: all 0.2s;
        }
        .toc a:hover {
            background: #e7f1ff;
            color: #0a58ca;
            padding-left: 1.2rem;
        }
        /* Main content */
        .content {
            margin-left: 280px;
            flex: 1;
            padding: 2rem;
            max-width: calc(100% - 280px);
        }
        .report-section {
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
            overflow: hidden;
        }
        .section-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #e9ecef;
            cursor: pointer;
            user-select: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-header:hover {
            background: #e9ecef;
        }
        .section-header h2 {
            font-size: 1.2rem;
            font-weight: 600;
            color: #0b5ed7;
        }
        .toggle-icon {
            font-size: 1.2rem;
            font-weight: bold;
            color: #6c757d;
        }
        .section-content {
            padding: 1.5rem;
            overflow-x: auto;
            display: block;
        }
        .section-content.collapsed {
            display: none;
        }
        pre {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 1rem;
            border-radius: 6px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
        }
        .search-container {
            margin-bottom: 1.5rem;
            background: #fff;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        .search-container input {
            flex: 1;
            padding: 0.5rem 0.8rem;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 1rem;
        }
        .search-container button {
            background: #0b5ed7;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .search-container button:hover {
            background: #0a58ca;
        }
        .highlight {
            background-color: #ffec99;
            color: #000;
        }
        .footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem;
            color: #6c757d;
            font-size: 0.8rem;
        }
        @media (max-width: 768px) {
            .toc {
                width: 100%;
                position: relative;
                height: auto;
                border-right: none;
                border-bottom: 1px solid #ddd;
            }
            .content {
                margin-left: 0;
                max-width: 100%;
                padding: 1rem;
            }
            .container {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="toc">
        <h2>📑 Table of Contents</h2>
        <ul>
"""
    # Build table of contents
    for sec in sections:
        html_content += f'            <li><a href="#{sec["id"]}">{html.escape(sec["title"])}</a></li>\n'
    html_content += """        </ul>
    </div>
    <div class="content">
        <div class="search-container">
            <input type="text" id="searchInput" placeholder="Search across all reports... (Ctrl+F for browser native)">
            <button id="searchButton">🔍 Search</button>
            <button id="clearSearch">✖ Clear</button>
        </div>
"""
    # Generate each section with collapsible content
    for sec in sections:
        escaped_content = html.escape(sec["content"])
        html_content += f"""
        <div class="report-section" id="{sec['id']}">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>{html.escape(sec['title'])}</h2>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="section-content">
                <pre>{escaped_content}</pre>
            </div>
        </div>
"""
    html_content += """
        <div class="footer">
            Generated by VolMenu • All plugin outputs are embedded.
        </div>
    </div>
</div>
<script>
    function toggleSection(header) {
        const content = header.nextElementSibling;
        const icon = header.querySelector('.toggle-icon');
        if (content.classList.contains('collapsed')) {
            content.classList.remove('collapsed');
            icon.textContent = '▼';
        } else {
            content.classList.add('collapsed');
            icon.textContent = '▶';
        }
    }
    // Search functionality (simple highlight)
    function performSearch() {
        const query = document.getElementById('searchInput').value.trim();
        if (query === "") {
            clearHighlights();
            return;
        }
        clearHighlights();
        const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
        const preElements = document.querySelectorAll('.section-content pre');
        preElements.forEach(pre => {
            const originalText = pre.innerText;
            const newHtml = originalText.replace(regex, '<span class="highlight">$1</span>');
            pre.innerHTML = newHtml;
        });
    }
    function clearHighlights() {
        const preElements = document.querySelectorAll('.section-content pre');
        preElements.forEach(pre => {
            const originalText = pre.innerText;
            pre.innerHTML = escapeHtml(originalText);
        });
    }
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    function escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
    }
    document.getElementById('searchButton').addEventListener('click', performSearch);
    document.getElementById('clearSearch').addEventListener('click', () => {
        document.getElementById('searchInput').value = '';
        clearHighlights();
    });
    document.getElementById('searchInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performSearch();
    });
    // Initially all sections are expanded, but we can collapse some if too many? Keep all expanded.
</script>
</body>
</html>
"""

    report_path = output_path / "volatility_report.html"
    try:
        report_path.write_text(html_content, encoding="utf-8")
        print(f"    HTML report generated: {report_path}")
    except Exception as e:
        print(f"    Failed to write HTML report: {e}")


# ---------------------------------------------------------------------------
# Scan configuration and execution (modified)
# ---------------------------------------------------------------------------
def select_memory_image():
    print("\nSelect the memory image to analyze.")
    print("(Press Enter to open the file picker, or type 'c' to cancel "
          "and return to the main menu.)")
    raw = input("> ").strip().lower()
    if raw == "c":
        raise Cancelled()

    path = pick_file(
        title="Select memory image",
        filetypes=(
            ("Memory images", "*.raw;*.mem;*.dmp;*.vmem;*.bin;*.img;*.lime"),
            ("All files", "*.*"),
        ),
    )
    if not path:
        print("No memory image selected.")
        return None
    return os.path.normpath(path)


def select_output_directory():
    print("\nSelect the output directory for results.")
    print("(Press Enter to open the folder picker, or type 'c' to cancel "
          "and return to the main menu.)")
    raw = input("> ").strip().lower()
    if raw == "c":
        raise Cancelled()

    path = pick_directory(title="Select output directory")
    if not path:
        print("No output directory selected.")
        return None
    return os.path.normpath(path)


def select_target_os():
    print("\nSelect the target operating system:")
    print(" 1. Windows")
    print(" 2. Linux")
    print(" 3. Mac")
    print(" C. Cancel (back to main menu)")
    while True:
        choice = input("Select an option: ").strip().lower()
        if choice == "1":
            return "windows"
        if choice == "2":
            return "linux"
        if choice == "3":
            return "mac"
        if choice == "c":
            raise Cancelled()
        print("Invalid option.")


def select_plugins(target_os):
    plugin_list = PLUGINS[target_os]
    items = list(plugin_list)
    extra_options = [
        ("Run ALL plugins", "ALL"),
        ("Cancel (back to main menu)", "CANCEL"),
    ]

    title = (f"Select {OS_LABELS[target_os]} plugins to run "
             f"(space = toggle, enter = confirm)")

    result = checkbox_menu(title, items, extra_options=extra_options)

    if result == "CANCEL":
        raise Cancelled()
    if result == "ALL":
        return list(plugin_list)

    return [plugin_list[i] for i in result]


def configure_scan():
    """Walk the user through configuring a single scan. Returns a dict
    representing the queued job, or None if a picker returned nothing.
    Raises Cancelled if the user explicitly cancels back to the main menu."""
    image_path = select_memory_image()
    if not image_path:
        return None

    output_dir = select_output_directory()
    if not output_dir:
        return None

    target_os = select_target_os()
    plugins = select_plugins(target_os)

    return {
        "image_path": image_path,
        "output_dir": output_dir,
        "target_os": target_os,
        "plugins": plugins,
    }


# ---------------------------------------------------------------------------
# Progress monitoring and output cleanup
# ---------------------------------------------------------------------------
_PROGRESS_RE = re.compile(r"Progress:\s*([0-9]+(?:\.[0-9]+)?)\s*(.*)")


def monitor_progress(out_file, stop_event, plugin_idx, total_plugins,
                      job_index, total_jobs):
    """Periodically read out_file and print the latest 'Progress: NN.NN ...'
    line found, until stop_event is set."""
    last_pct = None
    last_msg = None

    while not stop_event.is_set():
        time.sleep(0.5)
        try:
            with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except (FileNotFoundError, OSError):
            continue

        # Scan from the end for the most recent progress line
        for line in reversed(lines):
            match = _PROGRESS_RE.search(line)
            if match:
                pct = match.group(1)
                msg = match.group(2).strip()
                if (pct, msg) != (last_pct, last_msg):
                    last_pct, last_msg = pct, msg
                    status = f"    Progress: {pct}%"
                    if msg:
                        status += f" - {msg}"
                    status += (f"  [plugin {plugin_idx}/{total_plugins}, "
                                f"scan {job_index}/{total_jobs}]")
                    print(status)
                break


def clean_output_file(out_file):
    """Post-process a plugin's output file:
    - Remove every line that starts with 'Progress' (after stripping
      leading whitespace).
    - Collapse runs of more than one blank line down to a single blank
      line.
    """
    try:
        with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except (FileNotFoundError, OSError):
        return

    cleaned = []
    blank_run = 0

    for line in lines:
        if line.lstrip().startswith("Progress"):
            continue

        if line.strip() == "":
            blank_run += 1
            if blank_run > 1:
                continue
            cleaned.append(line)
        else:
            blank_run = 0
            cleaned.append(line)

    try:
        with open(out_file, "w", encoding="utf-8", errors="replace") as fh:
            fh.writelines(cleaned)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Scan execution (modified to generate HTML after each job)
# ---------------------------------------------------------------------------
def run_scan_job(vol_exe, job, job_index, total_jobs):
    image_path = os.path.normpath(job["image_path"])
    output_dir = os.path.normpath(job["output_dir"])
    plugins = job["plugins"]

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    perf_args = build_perf_args()

    symbols_dir = find_symbols_dir(vol_exe, job["target_os"])
    symbol_args = ["-s", os.path.normpath(symbols_dir)] if symbols_dir else []

    print("\n" + "#" * 60)
    print(f"# Scan {job_index}/{total_jobs}: {os.path.basename(image_path)} "
          f"[{OS_LABELS[job['target_os']]}]")
    if symbols_dir:
        print(f"# Using symbols directory: {os.path.normpath(symbols_dir)}")
    else:
        print("# No matching symbols subdirectory found next to vol.exe "
              "(continuing without -s)")
    print(f"# Plugins to run: {len(plugins)}")
    print("#" * 60)

    total_plugins = len(plugins)
    for plugin_idx, plugin in enumerate(plugins, start=1):
        out_file = Path(output_dir) / f"{plugin.replace('.', '_')}.txt"
        cmd = [vol_exe, *perf_args, *symbol_args, "-f", image_path, plugin]

        print(f"\n[{plugin_idx}/{total_plugins}] (Scan {job_index}/{total_jobs}) "
              f"Running: {plugin}")
        print(f"    Command: {' '.join(cmd)}")
        print(f"    Output -> {out_file}")
        print("    Status: RUNNING... (this may take a while, please wait)")

        try:
            # Truncate/create the file first so the monitor thread doesn't
            # read stale content from a previous run.
            with open(out_file, "w", encoding="utf-8", errors="replace"):
                pass

            stop_event = threading.Event()
            monitor_thread = threading.Thread(
                target=monitor_progress,
                args=(out_file, stop_event, plugin_idx, total_plugins,
                      job_index, total_jobs),
                daemon=True,
            )
            monitor_thread.start()

            creationflags = 0
            if sys.platform == "win32":
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
            with open(out_file, "a", encoding="utf-8", errors="replace") as fh:
                proc = subprocess.Popen(
                    cmd,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=creationflags,
                )
                returncode = proc.wait()

            stop_event.set()
            monitor_thread.join(timeout=2)

            clean_output_file(out_file)

            if returncode == 0:
                print(f"    Status: DONE [OK]  ({plugin_idx}/{total_plugins} complete)")
            else:
                print(f"    Status: DONE [WARN] Exit code {returncode} "
                      f"(see output file)  ({plugin_idx}/{total_plugins} complete)")
        except Exception as exc:
            print(f"    Status: ERROR - Failed to run plugin: {exc}")

    # === NEW: Generate the HTML report for this scan ===
    generate_html_report(output_dir, job)

    print(f"\nScan {job_index}/{total_jobs} complete. Results saved to: {output_dir}")


def run_queue(vol_exe, queue):
    if not queue:
        print("\nQueue is empty - nothing to run.")
        return

    total_jobs = len(queue)
    print(f"\nStarting {total_jobs} queued scan(s)...")
    for idx, job in enumerate(queue, start=1):
        run_scan_job(vol_exe, job, idx, total_jobs)
        print(f"\nOverall progress: {idx}/{total_jobs} scans complete.")

    print("\nAll queued scans complete.")


# ---------------------------------------------------------------------------
# New scan workflow (with queuing)
# ---------------------------------------------------------------------------
def new_scan_workflow(vol_exe):
    queue = []

    while True:
        try:
            job = configure_scan()
        except Cancelled:
            print("\nCancelled. Returning to main menu.")
            if queue:
                discard = input(
                    f"You have {len(queue)} queued scan(s). Discard them? (y/n): "
                ).strip().lower()
                if discard != "y":
                    run_queue(vol_exe, queue)
            return

        if job is None:
            print("\nScan configuration cancelled (no selection made).")
        else:
            queue.append(job)
            print(f"\nScan added to queue (position {len(queue)}).")
            print(f"  Image:   {job['image_path']}")
            print(f"  Output:  {job['output_dir']}")
            print(f"  OS:      {OS_LABELS[job['target_os']]}")
            print(f"  Plugins: {len(job['plugins'])} selected")

        again = input(
            "\nWould you like to queue another scan? (y/n, or 'c' to cancel "
            "and return to main menu): "
        ).strip().lower()
        if again == "c":
            print("\nCancelled. Returning to main menu.")
            if queue:
                discard = input(
                    f"You have {len(queue)} queued scan(s). Discard them? (y/n): "
                ).strip().lower()
                if discard != "y":
                    run_queue(vol_exe, queue)
            return
        if again != "y":
            break

    run_queue(vol_exe, queue)


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
def main_menu(vol_exe):
    while True:
        print("\n" + "=" * 50)
        print(" VolMenu - Volatility 3 Wrapper")
        print("=" * 50)
        print(f" vol.exe: {vol_exe}")
        print("-" * 50)
        print(" 1. New scan")
        print(" 2. Configure performance settings")
        print(" 3. Change vol.exe location")
        print(" 0. Exit")
        print("=" * 50)

        choice = input("Select an option: ").strip()

        if choice == "1":
            new_scan_workflow(vol_exe)
        elif choice == "2":
            show_performance_menu()
        elif choice == "3":
            vol_exe = change_vol_exe(vol_exe)
        elif choice == "0":
            print("Goodbye.")
            break
        else:
            print("Invalid option.")


def main():
    print("Starting VolMenu...")
    vol_exe = ensure_vol_exe()
    main_menu(vol_exe)


if __name__ == "__main__":
    main()
