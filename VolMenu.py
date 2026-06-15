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
PERF_PARALLELISM_VALUE = "ParallelismEnabled"
PERF_WORKERS_VALUE = "WorkerCount"
PERF_VERBOSE_VALUE = "VerboseOutput"
PERF_SMARTCACHE_VALUE = "SmartCacheEnabled"

VOLATILITY3_URL = "https://github.com/volatilityfoundation/volatility3"

DEFAULT_WORKERS = os.cpu_count() or 4

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
def show_performance_menu():
    while True:
        parallelism = reg_get_bool(PERF_PARALLELISM_VALUE, False)
        workers = reg_get_int(PERF_WORKERS_VALUE, DEFAULT_WORKERS)
        verbose = reg_get_bool(PERF_VERBOSE_VALUE, False)
        smartcache = reg_get_bool(PERF_SMARTCACHE_VALUE, True)

        print("\n" + "=" * 50)
        print(" Performance Configuration")
        print("=" * 50)
        print(f" 1. Parallelism (-p):        {'ON' if parallelism else 'OFF'}")
        print(f" 2. Worker count:            {workers}  (CPUs detected: {os.cpu_count()})")
        print(f" 3. Verbose output (-vvv):   {'ON' if verbose else 'OFF'}")
        print(f" 4. Smart layer caching:     {'ON' if smartcache else 'OFF'}")
        print(" 0. Back to main menu")
        print("=" * 50)

        choice = input("Select an option: ").strip()

        if choice == "1":
            reg_set(PERF_PARALLELISM_VALUE, not parallelism)
            print(f"Parallelism {'enabled' if not parallelism else 'disabled'}.")
        elif choice == "2":
            raw = input(f"Enter number of workers (1-{os.cpu_count() * 2}): ").strip()
            if raw.isdigit() and int(raw) > 0:
                reg_set(PERF_WORKERS_VALUE, int(raw))
                print(f"Worker count set to {raw}.")
            else:
                print("Invalid value.")
        elif choice == "3":
            reg_set(PERF_VERBOSE_VALUE, not verbose)
            print(f"Verbose output {'enabled' if not verbose else 'disabled'}.")
        elif choice == "4":
            reg_set(PERF_SMARTCACHE_VALUE, not smartcache)
            print(f"Smart layer caching {'enabled' if not smartcache else 'disabled'}.")
        elif choice == "0":
            return
        else:
            print("Invalid option.")


def build_perf_args():
    """Translate stored performance settings into vol.exe CLI args."""
    args = []
    if reg_get_bool(PERF_PARALLELISM_VALUE, False):
        # -p/--parallelism takes the number of workers as its argument
        # (NOT the same as -p/--plugin-dirs).
        workers = reg_get_int(PERF_WORKERS_VALUE, DEFAULT_WORKERS)
        args.extend(["-p", str(workers)])
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
# Scan configuration
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
# Scan execution
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

            with open(out_file, "a", encoding="utf-8", errors="replace") as fh:
                proc = subprocess.Popen(
                    cmd,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
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
