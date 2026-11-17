#!/usr/bin/env python3
"""
boftest.py — General-purpose BOF test driver for COFFLoader.

Provides a Python interface for testing any Cobalt Strike BOF through
the general-purpose COFFLoader harness.  Supports:
  - bof_pack argument packing (i, s, z, Z, b formats)
  - Single and multi-command execution
  - JSON structured output parsing
  - Test specs (inline or from file)

Usage:
    # Quick single command
    python boftest.py mybof.o i:0 Z:"hello"

    # Multi-command (stateful BOF)
    python boftest.py --multi mybof.o i:0 -- i:2 Z:whoami -- i:3

    # With assertions
    python boftest.py mybof.o i:0 --expect "success"

    # From test spec file
    python boftest.py --spec tests.json
"""

import argparse
import json
import os
import struct
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COFFLOADER = os.path.join(SCRIPT_DIR, "dist", "coffloader.exe")

# Fallback: check same directory
if not os.path.exists(COFFLOADER):
    COFFLOADER = os.path.join(SCRIPT_DIR, "coffloader.exe")


# ── bof_pack argument packing ──────────────────────────────────────────

def bof_pack_int(value):
    """Pack a 32-bit little-endian int."""
    return struct.pack("<I", value & 0xFFFFFFFF)

def bof_pack_short(value):
    """Pack a 16-bit little-endian short."""
    return struct.pack("<H", value & 0xFFFF)

def bof_pack_str(s):
    """Pack a length-prefixed ANSI string (null-terminated)."""
    if isinstance(s, str):
        s = s.encode("utf-8")
    data = s + b"\x00"
    return struct.pack("<I", len(data)) + data

def bof_pack_wstr(s):
    """Pack a length-prefixed wide string (UTF-16LE, null-terminated)."""
    if isinstance(s, str):
        s = s.encode("utf-16-le")
    data = s + b"\x00\x00"
    return struct.pack("<I", len(data)) + data

def bof_pack_blob(data):
    """Pack a length-prefixed binary blob."""
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return struct.pack("<I", len(data)) + data

def make_args_hex(packed_bytes):
    """Convert packed bytes to hex with size prefix for COFFLoader."""
    total = struct.pack("<I", len(packed_bytes) + 4) + packed_bytes
    return total.hex()

def pack_arg_spec(spec):
    """Pack a single arg spec string like 'i:42' or 'Z:hello'."""
    if len(spec) < 2 or spec[1] != ':':
        raise ValueError(f"Invalid arg spec: {spec}")

    atype = spec[0]
    value = spec[2:]

    if atype == 'i':
        return bof_pack_int(int(value, 0))
    elif atype == 's':
        return bof_pack_short(int(value, 0))
    elif atype == 'z':
        return bof_pack_str(value)
    elif atype == 'Z':
        return bof_pack_wstr(value)
    elif atype == 'b':
        if value.startswith('@'):
            with open(value[1:], 'rb') as f:
                return bof_pack_blob(f.read())
        else:
            return bof_pack_blob(value)
    else:
        raise ValueError(f"Unknown arg type: {atype}")

def pack_specs(specs):
    """Pack a list of arg spec strings into a single packed blob."""
    packed = b""
    for spec in specs:
        packed += pack_arg_spec(spec)
    return packed


# ── COFFLoader invocation ──────────────────────────────────────────────

def run_bof(bof_path, entry="go", commands=None, json_mode=True, timeout=180,
            inspect=False):
    """
    Run a BOF through COFFLoader.

    Args:
        bof_path: Path to the .x64.o file
        entry: Entry function name (default: "go")
        commands: List of command dicts, each with 'args' (list of spec strings)
                  or 'hex' (raw hex string)
        json_mode: Use JSON structured output
        timeout: Execution timeout in seconds
        inspect: Parse, resolve, and report metadata without executing

    Returns:
        dict with 'status', 'commands' (list of result dicts), 'raw_output'
    """
    if not os.path.exists(COFFLOADER):
        raise FileNotFoundError(
            f"COFFLoader not found at {COFFLOADER}\n"
            f"Build it: cd coffloader && nmake"
        )

    if commands is None:
        commands = [{"args": []}]

    # Build command line
    cmd = [COFFLOADER]
    if json_mode:
        cmd.append("--json")
    if inspect:
        cmd.append("--inspect")

    use_hex = any("packed" in command or "hex" in command for command in commands)

    if len(commands) > 1 and not use_hex:
        cmd.append("--multi")

    cmd.extend([entry, bof_path])

    # Add arguments
    for i, command in enumerate(commands):
        if i > 0 and not use_hex:
            cmd.append("--")

        if use_hex:
            if "hex" in command:
                hex_str = command["hex"]
            elif "packed" in command:
                hex_str = make_args_hex(command["packed"])
            else:
                hex_str = make_args_hex(pack_specs(command.get("args", [])))
            cmd.extend(["--hex", hex_str])
        elif "hex" in command:
            cmd.extend(["--hex", command["hex"]])
        elif "args" in command:
            cmd.extend(command["args"])
        elif "packed" in command:
            # Pre-packed bytes — convert to hex for --hex mode
            hex_str = make_args_hex(command["packed"])
            # Switch to hex mode for this command
            cmd = [COFFLOADER]
            if json_mode:
                cmd.append("--json")
            cmd.extend([entry, bof_path, "--hex", hex_str])

    # Run
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout
    )

    raw_output = result.stdout
    if result.stderr:
        raw_output += result.stderr

    # Parse JSON output
    if json_mode:
        try:
            parsed = json.loads(result.stdout)
            parsed["raw_output"] = raw_output
            parsed["exit_code"] = result.returncode
            if (parsed.get("schema") != "coffloader/v2"
                    or parsed.get("schema_version") != 2):
                return {
                    "status": "contract_error",
                    "error": "Expected coffloader/v2 JSON contract",
                    "commands": parsed.get("commands", []),
                    "raw_output": raw_output,
                    "exit_code": result.returncode,
                }
            return parsed
        except json.JSONDecodeError:
            return {
                "status": "parse_error",
                "error": "Failed to parse JSON output",
                "raw_output": raw_output,
                "exit_code": result.returncode,
            }
    else:
        return {
            "status": "ok" if result.returncode == 0 else "error",
            "raw_output": raw_output,
            "exit_code": result.returncode,
        }


def run_bof_simple(bof_path, *arg_specs, entry="go", timeout=180):
    """
    Convenience: run a BOF with arg specs and return the output string.

    Example:
        output = run_bof_simple("mybof.o", "i:0", "Z:hello")
    """
    result = run_bof(bof_path, entry=entry,
                     commands=[{"args": list(arg_specs)}],
                     json_mode=True, timeout=timeout)

    if result.get("commands") and result["commands"][0].get("output"):
        return result["commands"][0]["output"]
    return result.get("raw_output", "")


# ── Test spec execution ────────────────────────────────────────────────

def run_test_spec(spec, bof_path=None):
    """
    Run a test specification.

    Spec format:
    {
        "bof": "path/to/bof.o",     # or passed via bof_path arg
        "entry": "go",               # optional, default "go"
        "tests": [
            {
                "name": "init",
                "args": ["i:0"],
                "expect_output": "initialized",
                "expect_no_crash": true
            },
            ...
        ]
    }

    For stateful (multi-command) tests:
    {
        "bof": "path/to/bof.o",
        "multi": true,
        "commands": [
            {"name": "INIT", "args": ["i:0"], "expect": "initialized"},
            {"name": "EXEC", "args": ["i:2", "Z:whoami"], "expect": "\\\\"},
            {"name": "DESTROY", "args": ["i:3"], "expect": "destroyed"}
        ]
    }
    """
    bof = bof_path or spec.get("bof")
    if not bof:
        raise ValueError("No BOF path specified")

    entry = spec.get("entry", "go")
    results = []

    def run_error(result, expected_count):
        status = result.get("status")
        if status not in ("ok", "completed"):
            detail = result.get("legacy_status") or result.get("error", {}).get("code")
            return f"Harness status is '{status or 'missing'}' ({detail or 'no detail'})"
        if status == "completed" and not result.get("summary", {}).get("ok", False):
            return "Harness completed with one or more failed commands"
        if result.get("exit_code", 0) != 0:
            return f"Harness exited with code {result.get('exit_code')}"
        actual_count = len(result.get("commands", []))
        if actual_count != expected_count:
            return f"Expected {expected_count} command result(s), got {actual_count}"
        return None

    if spec.get("multi"):
        # Multi-command mode — all commands in single process
        commands = []
        for cmd_spec in spec["commands"]:
            commands.append({"args": cmd_spec.get("args", [])})

        result = run_bof(bof, entry=entry, commands=commands, json_mode=True)
        harness_error = run_error(result, len(commands))

        for i, cmd_spec in enumerate(spec["commands"]):
            name = cmd_spec.get("name", f"CMD_{i}")
            cmd_result = result.get("commands", [{}])[i] if i < len(result.get("commands", [])) else {}
            output = cmd_result.get("output", "")
            status = cmd_result.get("status", "missing")

            passed = True
            reason = "OK"

            if harness_error:
                passed = False
                reason = harness_error
            elif status not in ("ok", "crash"):
                passed = False
                reason = f"Unexpected command status '{status}'"
            elif cmd_spec.get("expect_no_crash", True) and status == "crash":
                passed = False
                reason = f"Crashed: {cmd_result.get('exception', 'unknown')}"

            if "expect" in cmd_spec and cmd_spec["expect"] not in output:
                passed = False
                reason = f"Expected '{cmd_spec['expect']}' not found in output"

            if "reject" in cmd_spec and cmd_spec["reject"] in output:
                passed = False
                reason = f"Rejected string '{cmd_spec['reject']}' found in output"

            results.append({
                "name": name,
                "passed": passed,
                "reason": reason,
                "output": output[:500],  # truncate for display
            })
    else:
        # Individual tests — each in its own process
        for test in spec.get("tests", []):
            name = test.get("name", "unnamed")
            args = test.get("args", [])

            result = run_bof(bof, entry=entry,
                           commands=[{"args": args}],
                           json_mode=True)
            harness_error = run_error(result, 1)

            cmd_result = result.get("commands", [{}])[0] if result.get("commands") else {}
            output = cmd_result.get("output", "")
            status = cmd_result.get("status", "missing")

            passed = True
            reason = "OK"

            if harness_error:
                passed = False
                reason = harness_error
            elif status not in ("ok", "crash"):
                passed = False
                reason = f"Unexpected command status '{status}'"
            elif test.get("expect_no_crash", True) and status == "crash":
                passed = False
                reason = f"Crashed: {cmd_result.get('exception', 'unknown')}"

            if "expect_output" in test and test["expect_output"] not in output:
                passed = False
                reason = f"Expected '{test['expect_output']}' not found"

            results.append({
                "name": name,
                "passed": passed,
                "reason": reason,
                "output": output[:500],
            })

    return results


def print_results(results):
    """Print test results in a readable format."""
    print(f"\n{'='*60}")
    print("  RESULTS")
    print(f"{'='*60}")

    passed = 0
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['name']}", end="")
        if not r["passed"]:
            print(f" -- {r['reason']}", end="")
        print()
        if r["passed"]:
            passed += 1

    print(f"\n  {passed}/{len(results)} passed")
    return passed == len(results)


# ── CLI ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="General-purpose BOF test driver",
        epilog="Examples:\n"
               "  %(prog)s mybof.o i:0 Z:hello\n"
               "  %(prog)s --multi mybof.o i:0 -- i:2 Z:whoami -- i:3\n"
               "  %(prog)s --spec tests.json\n"
               "  %(prog)s --spec tests.json --bof mybof.o\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("bof", nargs="?", help="Path to BOF .x64.o file")
    parser.add_argument("args", nargs="*", help="Arg specs (i:N, z:str, Z:wstr, b:hex)")
    parser.add_argument("--entry", default="go", help="Entry function name (default: go)")
    parser.add_argument("--multi", action="store_true", help="Multi-command mode")
    parser.add_argument("--expect", help="Assert this string appears in output")
    parser.add_argument("--spec", help="Path to JSON test spec file")
    parser.add_argument("--json", action="store_true", help="Raw JSON output from COFFLoader")
    parser.add_argument("--inspect", action="store_true",
                        help="Inspect and resolve the BOF without executing it")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds")

    args = parser.parse_args()

    # ── Test spec mode ──
    if args.spec:
        with open(args.spec) as f:
            spec = json.load(f)
        results = run_test_spec(spec, bof_path=args.bof)
        all_passed = print_results(results)
        sys.exit(0 if all_passed else 1)

    # ── Direct execution mode ──
    if not args.bof:
        parser.print_help()
        sys.exit(1)

    if args.multi:
        # Split on -- to get commands
        commands = []
        current_args = []
        for a in args.args:
            if a == "--":
                commands.append({"args": current_args})
                current_args = []
            else:
                current_args.append(a)
        if current_args:
            commands.append({"args": current_args})

        result = run_bof(args.bof, entry=args.entry, commands=commands,
                        json_mode=True, timeout=args.timeout,
                        inspect=args.inspect)
    else:
        result = run_bof(args.bof, entry=args.entry,
                        commands=[{"args": args.args}],
                        json_mode=True, timeout=args.timeout,
                        inspect=args.inspect)

    # ── Output ──
    if args.json or args.inspect:
        print(json.dumps(result, indent=2))
    else:
        # Print each command's output
        for i, cmd in enumerate(result.get("commands", [])):
            if len(result.get("commands", [])) > 1:
                print(f"\n--- Command {i+1} [{cmd.get('status', '?')}] ---")
            if cmd.get("output"):
                print(cmd["output"], end="")
            if cmd.get("status") == "crash":
                print(f"\n[!] CRASH: {cmd.get('exception', 'unknown')}")

        # Check assertions
        if args.expect:
            full_output = " ".join(
                cmd.get("output", "") for cmd in result.get("commands", [])
            )
            if args.expect in full_output:
                print(f"\n[PASS] Found expected: '{args.expect}'")
            else:
                print(f"\n[FAIL] Expected '{args.expect}' not found in output")
                sys.exit(1)

    # Exit with error on load/parse failures or non-successful commands.
    if result.get("status") not in ("ok", "completed") or result.get("exit_code", 0) != 0:
        sys.exit(1)
    if result.get("status") == "completed" and not result.get("summary", {}).get("ok", False):
        sys.exit(1)
    if any(c.get("status") != "ok" for c in result.get("commands", [])):
        sys.exit(1)


if __name__ == "__main__":
    main()
