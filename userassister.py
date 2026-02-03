#!/usr/bin/env python3
"""
userassister :: UserAssist Parser (NTUSER.DAT)
version 2.0.0

extracts binary data that Registry Explorer etc. may not.

made by luminary (luminary@daybreak.sh)

usage:
  python3 userassister.py --hive NTUSER.DAT

"""

import argparse
import csv
import os
import re
import struct
import sys
from datetime import datetime, timezone, timedelta

try:
    from Registry import Registry
except Exception as e:
    sys.stderr.write(
        "[!] Missing dependency 'python-registry'\n"
    )
    raise

USERASSIST_ROOT = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
COUNT_NAME = "Count"
EPOCH_FILETIME = datetime(1601, 1, 1, tzinfo=timezone.utc)

def rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

def filetime_to_iso(ft: int):
    if not ft:
        return None
    try:
        dt = EPOCH_FILETIME + timedelta(microseconds=ft/10)
        return dt.isoformat()
    except Exception:
        return None

def parse_v5(blob: bytes):
    """
    Modern UserAssist (Vista+), expected >= 72 bytes:
      0x00 u32 session_id
      0x04 u32 run_count
      0x08 u32 focus_count
      0x0C u32 focus_time_ms   (RELIABLE: milliseconds)
      0x10..0x34 10 * float32  (usage ring; not required)
      0x38 u32  r0_last_index
      0x3C u64  last_exec FILETIME (RELIABLE timestamp)
      0x44 u32  unknown
    """
    if len(blob) < 0x48:
        raise ValueError("Too short for v5")
    session_id, run_count, focus_count, focus_time_ms = struct.unpack_from("<IIII", blob, 0x00)
    last_exec_raw = struct.unpack_from("<Q", blob, 0x3C)[0]
    return {
        "layout": "v5",
        "run_count": run_count,
        "focus_count": focus_count,
        "focus_time_ms": focus_time_ms,
        "focus_time_s": round(focus_time_ms/1000.0, 3) if focus_time_ms is not None else None,
        "last_exec_filetime": last_exec_raw,
        "last_exec_iso_utc": filetime_to_iso(last_exec_raw),
        "blob_len": len(blob),
    }

def parse_xp_min(blob: bytes):
    """
    XP-era minimal heuristic:
      run_count @ 0x04 (u32) if present
      last_exec @ 0x08 (u64 FILETIME) if present
    Note: XP often seeds run_count at 5.
    """
    run_count = struct.unpack_from("<I", blob, 0x04)[0] if len(blob) >= 8 else None
    last_exec_raw = struct.unpack_from("<Q", blob, 0x08)[0] if len(blob) >= 16 else None
    return {
        "layout": "xp/min",
        "run_count": run_count,
        "focus_count": None,
        "focus_time_ms": None,
        "focus_time_s": None,
        "last_exec_filetime": last_exec_raw,
        "last_exec_iso_utc": filetime_to_iso(last_exec_raw) if last_exec_raw else None,
        "blob_len": len(blob),
        "note": "XP often seeds run_count at 5; subtract 5 if appropriate.",
    }

def parse_blob(blob: bytes):
    # prefer modern layout when size >= 72; otherwise try XP/min.
    try:
        if len(blob) >= 0x48:
            return parse_v5(blob)
        return parse_xp_min(blob)
    except Exception as e:
        return {"layout": "unknown", "blob_len": len(blob), "error": str(e)}

def iter_userassist(reg: Registry.Registry):
    """Yield (guid, value_name_raw, value_name_rot13, parsed_dict)."""
    try:
        root = reg.open(USERASSIST_ROOT)
    except Registry.RegistryKeyNotFoundException:
        return

    for guid_key in root.subkeys():
        guid = guid_key.name()
        # find 'Count' subkey
        count = None
        for sk in guid_key.subkeys():
            if sk.name().lower() == COUNT_NAME.lower():
                count = sk
                break
        if not count:
            continue

        for v in count.values():
            vname = v.name() or ""
            decoded = rot13(vname) if vname else ""
            data = v.value()
            if isinstance(data, str):
                data = data.encode("utf-8", errors="ignore")
            parsed = parse_blob(data if isinstance(data, (bytes, bytearray)) else b"")
            yield guid, vname, decoded, parsed

# -----------------------------
# username / hostname helpers
# -----------------------------

_USER_SHELL_FOLDERS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
_SHELL_FOLDERS      = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
_EXPLORER_KEY       = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
_ENVIRONMENT        = r"Environment"
_VOLATILE_ENV       = r"Volatile Environment"

_USERNAME_CANDIDATE_VALUES = [
    # from Shell Folders (expanded)
    ("Shell Folders", "Desktop"),
    ("Shell Folders", "AppData"),
    ("Shell Folders", "Personal"),   # Documents
    ("Shell Folders", "Favorites"),
    # from Explorer direct (rare)
    ("Explorer", "Logon User Name"),
]

_USERS_RE = re.compile(r"\\Users\\([^\\]+)\\", re.IGNORECASE)
_DOCSNT_RE = re.compile(r"\\Documents and Settings\\([^\\]+)\\", re.IGNORECASE)

def _safe_open(reg: Registry.Registry, path: str):
    try:
        return reg.open(path)
    except Exception:
        return None

def _get_value(key, name: str):
    if not key:
        return None
    try:
        return key.value(name).value()
    except Exception:
        return None

def extract_username(reg: Registry.Registry):
    """
    best-effort username extraction from NTUSER.DAT:
    1) Explorer 'Logon User Name' (if present)
    2) parse from expanded paths in 'Shell Folders'
    3) expanded %USERPROFILE% in 'User Shell Folders'
    """
    # 1) direct Explorer value
    explorer = _safe_open(reg, _EXPLORER_KEY)
    direct = _get_value(explorer, "Logon User Name")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()

    # 2) parse from Shell Folders (expanded)
    shell = _safe_open(reg, _SHELL_FOLDERS)
    for _, valname in _USERNAME_CANDIDATE_VALUES:
        if _ == "Shell Folders":
            path = _get_value(shell, valname)
            if isinstance(path, str):
                m = _USERS_RE.search(path) or _DOCSNT_RE.search(path)
                if m:
                    return m.group(1)

    # 3) sometimes User Shell Folders has expanded USERPROFILE
    user_shell = _safe_open(reg, _USER_SHELL_FOLDERS)
    up = _get_value(user_shell, "UserProfile") or _get_value(user_shell, "Profile")
    if isinstance(up, str) and "%" not in up:
        m = _USERS_RE.search(up) or _DOCSNT_RE.search(up)
        if m:
            return m.group(1)

    # Could not determine
    return None

def extract_hostname(reg: Registry.Registry):
    """
    best effort only:
    - HKCU\\Volatile Environment\\COMPUTERNAME 
    - HKCU\\Environment\\COMPUTERNAME 
    returns None if not present.
    """
    ve = _safe_open(reg, _VOLATILE_ENV)
    hn = _get_value(ve, "COMPUTERNAME")
    if isinstance(hn, str) and hn.strip():
        return hn.strip()

    env = _safe_open(reg, _ENVIRONMENT)
    hn = _get_value(env, "COMPUTERNAME")
    if isinstance(hn, str) and hn.strip():
        return hn.strip()

    return None

# -----------------------------

def discover_default_hive():
    here = os.getcwd()
    candidate = os.path.join(here, "NTUSER.DAT")
    return candidate if os.path.isfile(candidate) else None

def find_hive_files(root_dir):
    """Walk *root_dir* and yield paths whose basename is NTUSER.DAT (case-insensitive)."""
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fn in filenames:
            if fn.upper() == "NTUSER.DAT":
                yield os.path.join(dirpath, fn)

def process_hive(hive_path):
    """Open a single hive, return (username, hostname, rows) or raise on failure."""
    reg = Registry.Registry(hive_path)
    username = extract_username(reg) or ""
    hostname = extract_hostname(reg) or ""

    rows = []
    for guid, raw_name, rot_name, parsed in iter_userassist(reg):
        rows.append({
            "hive_path": hive_path,
            "username": username,
            "hostname": hostname,
            "guid": guid,
            "value_name_raw": raw_name,
            "value_name_rot13": rot_name,
            "layout": parsed.get("layout"),
            "blob_len": parsed.get("blob_len"),
            "run_count": parsed.get("run_count"),
            "focus_count": parsed.get("focus_count"),
            "focus_time_ms": parsed.get("focus_time_ms"),
            "focus_time_s": parsed.get("focus_time_s"),
            "last_exec_filetime": parsed.get("last_exec_filetime"),
            "last_exec_iso_utc": parsed.get("last_exec_iso_utc"),
            "note": parsed.get("note"),
            "error": parsed.get("error"),
        })
    return username, hostname, rows

def _print_hive_table(rows, username, hostname, hive_path):
    """Print a per-hive stdout section with header and entry rows."""
    print(f"\n=== {hive_path} ===")
    print(f"{username}  @  {hostname}")
    print(f"{'GUID':38}  {'Decoded Name':60}  {'Run':>5}  {'Focus(ms)':>10}  {'Last Exec (UTC)':25}")
    print("-"*38 + "  " + "-"*60 + "  " + "-"*5 + "  " + "-"*10 + "  " + "-"*25)
    for r in rows:
        print(f"{r['guid']:<38}  {r['value_name_rot13'][:60]:<60}  "
              f"{(r['run_count'] if r['run_count'] is not None else ''):>5}  "
              f"{(r['focus_time_ms'] if r['focus_time_ms'] is not None else ''):>10}  "
              f"{(r['last_exec_iso_utc'] or ''):25}")

def main():
    ap = argparse.ArgumentParser(description="UserAssist parser for NTUSER.DAT (focus time & timestamps).")
    ap.add_argument("--hive", help="path to NTUSER.DAT (defaults to ./NTUSER.DAT if present)")
    ap.add_argument("-r", "--recurse", nargs="?", const=".", default=None,
                    help="recurse through directory (default: .) to find all NTUSER.DAT files")
    ap.add_argument("--out", default="", help="optional output CSV filename")
    args = ap.parse_args()

    # Collect hive paths to process
    hive_paths = []
    if args.recurse is not None:
        root = args.recurse
        if not os.path.isdir(root):
            sys.stderr.write(f"[!] not a directory: {root}\n")
            sys.exit(1)
        hive_paths = sorted(find_hive_files(root))
        if not hive_paths:
            sys.stderr.write(f"[!] no NTUSER.DAT files found under {root}\n")
            sys.exit(1)
    else:
        single = args.hive or discover_default_hive()
        if not single:
            sys.stderr.write("[!] provide --hive PATH, -r DIR, or place NTUSER.DAT in the current directory.\n")
            sys.exit(1)
        hive_paths = [single]

    # Process each hive
    all_rows = []
    for hp in hive_paths:
        try:
            username, hostname, rows = process_hive(hp)
        except Exception as e:
            sys.stderr.write(f"[!] failed to open hive: {hp}\n    {e}\n")
            continue
        if rows:
            _print_hive_table(rows, username, hostname, hp)
            all_rows.extend(rows)

    if not all_rows:
        sys.stderr.write("[!] no UserAssist entries found.\n")
        sys.exit(3)

    # Determine CSV filename
    fieldnames = [
        "hive_path","username","hostname","guid","value_name_raw","value_name_rot13","layout","blob_len",
        "run_count","focus_count","focus_time_ms","focus_time_s",
        "last_exec_filetime","last_exec_iso_utc","note","error"
    ]

    if args.out:
        csvOutput = args.out
    elif args.recurse is not None:
        csvOutput = "UserAssist_recursive.csv"
    else:
        username = all_rows[0]["username"]
        hostname = all_rows[0]["hostname"]
        csvOutput = f"UserAssist_{hostname}_{username}.csv"

    try:
        with open(csvOutput, "w", newline="", encoding="utf-8") as fp:
            w = csv.DictWriter(fp, fieldnames=fieldnames)
            w.writeheader()
            for r in all_rows:
                w.writerow(r)
    except Exception as e:
        sys.stderr.write(f"[!] could not write CSV {csvOutput}: {e}\n")

    sys.stderr.write(f"\n")

if __name__ == "__main__":
    main()

