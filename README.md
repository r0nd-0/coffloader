# COFFLoader

A Windows x64 harness for developing, inspecting, executing, and testing
Cobalt Strike Beacon Object Files (BOFs) outside of Beacon.

COFFLoader supports objects produced by both MSVC and MinGW, exposes a
versioned JSON interface for automation, and returns structured diagnostics
for malformed objects, unresolved imports, callback errors, and native faults.
It is intended for controlled defensive research, detection engineering, and
repeatable BOF development.

## Highlights

- MSVC `__imp_` pointer-slot imports and MinGW bare-symbol dispatch
- Executable near trampolines for MinGW function imports
- Bare data imports kept as data, never converted into code thunks
- Contiguous section allocation for safe x64 `REL32` relocations
- Writable relocation followed by final RX/RW/R page protections
- Validated x64 `.pdata` registration through `RtlAddFunctionTable`
- Selected hardware-fault capture with symbol and section resolution
- Stateful multi-command execution for `BeaconAddValue` workflows
- Versioned `coffloader/v2` JSON output and artifact SHA-256 correlation
- Python driver and MSVC/MinGW regression fixtures

## Contents

- [Requirements](#requirements)
- [Build](#build)
- [Quick start](#quick-start)
- [Argument format](#argument-format)
- [Inspection workflow](#inspection-workflow)
- [JSON and automation](#json-and-automation)
- [Python driver](#python-driver)
- [Crash and unwind diagnostics](#crash-and-unwind-diagnostics)
- [Beacon compatibility](#beacon-compatibility)
- [Architecture](#architecture)
- [Testing](#testing)
- [Security boundaries](#security-boundaries)
- [License and attribution](#license-and-attribution)
- [AI-agent workflow](#ai-agent-workflow)

## Requirements

- Windows x64
- Visual Studio 2022 C++ build tools
- A Windows SDK
- Python 3 for the regression suite and `boftest.py`
- MSYS2 MinGW-w64 `x86_64-w64-mingw32-gcc` on `PATH` for MinGW fixtures

Run build commands from an x64 Visual Studio Developer Command Prompt or a
PowerShell session initialized with `vcvars64.bat`.

## Build

```powershell
nmake
```

The release executable is written to:

```text
dist\coffloader.exe
```

Other build targets:

```powershell
nmake debug              # Debug executable with loader diagnostics
nmake mingw-fixtures     # Rebuild only the MinGW test objects
nmake test               # Build all fixtures and run regressions
nmake clean              # Remove generated artifacts
```

## Quick start

Inspect a BOF before execution:

```powershell
.\dist\coffloader.exe --inspect go .\path\example.x64.o
```

Execute with an integer and a wide string:

```powershell
.\dist\coffloader.exe go .\path\example.x64.o i:0 Z:"hello world"
```

Request machine-readable output:

```powershell
.\dist\coffloader.exe --json go .\path\example.x64.o i:0
```

Execute several commands against one loaded BOF:

```powershell
.\dist\coffloader.exe --multi go .\path\stateful.x64.o `
    i:0 -- `
    i:2 Z:whoami -- `
    i:3
```

Use `--trace` with either text or JSON mode to record Beacon compatibility API
calls made by the BOF.

## Argument format

Arguments use the familiar `bof_pack` notation:

| Syntax | Packed value | Example |
| --- | --- | --- |
| `i:<value>` | 32-bit integer | `i:42`, `i:0xFF` |
| `s:<value>` | 16-bit integer | `s:1` |
| `z:<text>` | Length-prefixed ANSI string | `z:hostname` |
| `Z:<text>` | Length-prefixed UTF-16 string | `Z:"Get-Process"` |
| `b:<hex>` | Length-prefixed binary data | `b:deadbeef` |
| `b:@<path>` | Length-prefixed file contents | `b:@payload.bin` |

For already packed buffers, use legacy hex mode:

```powershell
.\dist\coffloader.exe go .\path\example.x64.o `
    --hex 0800000000000000
```

Multiple `--hex` values execute as separate commands.

## Inspection workflow

`--inspect` parses and relocates the object, resolves imports, applies final
page protections, validates/registers unwind metadata, and emits JSON without
calling the requested BOF entry point.

Require both of these fields before execution:

```json
{
  "status": "ok",
  "phase": "inspect"
}
```

Review the returned:

- compiler profile
- section names, sizes, characteristics, and final protections
- relocation and symbol counts
- import provider, dispatch type, and resolved address
- `.pdata` section, function-table, and runtime-function counts

Inspection is analysis, not sandboxing. Resolving an arbitrary external module
can load that DLL and execute its `DllMain`; use trusted objects and providers.

## JSON and automation

Every JSON response identifies the contract explicitly:

```json
{
  "schema": "coffloader/v2",
  "schema_version": 2,
  "run_id": "4120-28194812",
  "loader": {
    "version": "0.2.0",
    "build": "Nov 17 2026 10:45:00"
  },
  "artifact": {
    "path": "example.x64.o",
    "size": 2206,
    "sha256": "..."
  },
  "status": "completed",
  "phase": "execute",
  "commands": [
    {
      "index": 0,
      "status": "ok",
      "output": "initialized\n"
    }
  ],
  "summary": {
    "ok": true,
    "command_count": 1,
    "crash_count": 0,
    "callback_error_count": 0
  }
}
```

A successful process launch is not sufficient. Automation should require:

1. top-level `status` equals `completed`;
2. every command has `status: "ok"`;
3. `summary.ok` is `true`; and
4. the process exit code is zero.

Stable phases currently include `input`, `parse`, `resolve`, `relocate`,
`unwind`, `protect`, `inspect`, and `execute`.

## Python driver

`boftest.py` wraps the JSON interface for scripts and AI-assisted iteration:

```powershell
python .\boftest.py --inspect .\path\example.x64.o
python .\boftest.py --json .\path\example.x64.o i:0 Z:hello
python .\boftest.py --spec .\tests.json
```

Python API example:

```python
from boftest import run_bof

result = run_bof(
    "example.x64.o",
    commands=[
        {"args": ["i:0"]},
        {"args": ["i:2", "Z:whoami"]},
    ],
)

assert result["status"] == "completed"
assert result["summary"]["ok"] is True
```

Test specification example:

```json
{
  "bof": "path/to/example.x64.o",
  "entry": "go",
  "multi": true,
  "commands": [
    {
      "name": "initialize",
      "args": ["i:0"],
      "expect": "initialized",
      "reject": "error",
      "expect_no_crash": true
    }
  ]
}
```

## Crash and unwind diagnostics

MSVC x64 `.pdata` contributions are validated after relocation and registered
with Windows. Function tables are removed before the image is released.
Malformed metadata fails closed with an `unwind`-phase error.

For selected synchronous faults, command JSON includes:

- native exception code and symbolic name
- instruction address
- raw exception parameters
- read, write, or execute operation when supplied by Windows
- accessed address and in-page status where applicable
- nearest COFF symbol and offset
- section name, index, and offset
- whether the instruction address was inside the BOF image

Software-raised exceptions are allowed to continue to normal RPC, C++/CLR,
and application SEH handlers. Stack overflow is intentionally not intercepted.

## Beacon compatibility

The compatibility layer implements the commonly used data, output, formatting,
key/value, token, and utility APIs. Some process-injection and spawn functions
remain local-test stubs.

| Area | Status |
| --- | --- |
| `BeaconData*` parsing | Implemented with bounds checks |
| `BeaconPrintf` and `BeaconOutput` | Buffered and captured |
| `BeaconFormat*` | Implemented with capacity checks |
| `BeaconAddValue/GetValue/RemoveValue` | 16-slot local store |
| Token helpers | Partial/local behavior |
| Spawn and injection helpers | Stubbed for local testing |
| `toWideChar` | Implemented |
| Win32 dynamic imports | Passed through |
| `__C_specific_handler` | Resolved for MSVC SEH |
| `__ImageBase` | Resolved to the loaded COFF base |

Compatibility with this harness does not prove identical behavior inside a
specific C2 or Beacon implementation. Validate important BOFs in their final
authorized test environment as well.

## Architecture

| File | Responsibility |
| --- | --- |
| `src/main.c` | Run orchestration and result lifecycle |
| `src/bof_cli.c/.h` | CLI parsing, argument packing, file input, SHA-256 |
| `src/json_output.c/.h` | Schema envelope, inspection, command/crash JSON |
| `src/crash_guard.c/.h` | VEH installation, native context recovery, fault details |
| `src/coffloader.c/.h` | COFF validation, allocation, relocation, imports, unwind registration |
| `src/beacon_compat.c/.h` | Beacon compatibility API and output/trace buffers |
| `boftest.py` | Python automation and test-spec runner |
| `test/` | MSVC/MinGW fixtures and regression tests |
| `AGENTS.md` | Repository contract and workflow for coding agents |

The CLI and `coffloader/v2` JSON contract are the stable automation boundary.
An MCP adapter, if added later, should remain a thin child-process wrapper
around this interface rather than embedding BOF execution in the MCP process.

## Testing

Run the complete suite:

```powershell
nmake clean
nmake test
```

The suite covers:

- MSVC and MinGW objects
- bare function and data imports
- stateful multi-command packing
- callback error propagation
- unresolved imports
- truncated and malformed COFF records
- `.pdata` validation and BOF-frame SEH unwinding
- deliberate access-violation capture
- inspect-mode and schema fields

For warning review:

```powershell
cl /nologo /W4 /Zs `
    src\main.c src\bof_cli.c src\json_output.c src\crash_guard.c `
    src\coffloader.c src\beacon_compat.c
```

## Security boundaries

- COFFLoader executes BOFs in its own process with the caller's privileges.
- It does not virtualize Windows APIs, files, registry, network, or tokens.
- Crash recovery is a debugging aid, not process integrity isolation.
- Continuing after a recovered native fault can observe corrupted state.
- `--inspect` does not invoke `go`, but import resolution can load DLLs.
- Keep secrets, production credentials, and sensitive data out of test specs
  and captured JSON artifacts.

For stronger isolation, launch one CLI process per test inside a disposable VM
or other operating-system isolation boundary and enforce an external timeout.

## License and attribution

This project is derived from
[TrustedSec COFFLoader](https://github.com/trustedsec/COFFLoader). The original
copyright, redistribution conditions, and warranty disclaimer are preserved in
[`LICENSE.txt`](LICENSE.txt). Changes in this repository add MSVC/MinGW
compatibility, structured inspection and diagnostics, unwind registration,
testing, and automation features; they are not endorsed by TrustedSec.

## AI-agent workflow

Coding agents should read [`AGENTS.md`](AGENTS.md) before changing the loader.
It defines the required build/test loop, module ownership, loader invariants,
result interpretation rules, and definition of done.

The recommended iteration loop is:

1. compile the BOF with MSVC or MinGW;
2. inspect and resolve it;
3. execute through JSON or `boftest.py`;
4. treat any command error, crash, timeout, or nonzero exit as a failure;
5. correlate the run ID and artifact SHA-256 with detection telemetry;
6. change one layer at a time and rerun the regression suite.
