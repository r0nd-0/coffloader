# AI Development Guide

This repository is a defensive BOF research harness. These instructions apply
to coding agents, automated refactoring tools, and human contributors using AI
assistance. Preserve a repeatable compile, inspect, execute, and detection-
validation workflow for both MSVC and MinGW x64 COFF objects.

## Safety and scope

- Treat every BOF as arbitrary native code. The loader is not a sandbox.
- Use only trusted fixtures on a disposable Windows lab system.
- Do not add features that conceal execution, bypass security controls, or
  silently change the caller's privileges.
- Do not place credentials, tokens, target data, or sensitive telemetry in the
  repository, test specifications, or committed JSON output.
- `--inspect` does not call the BOF entry point, but import resolution may call
  `LoadLibrary` and therefore execute a provider DLL's `DllMain`.

## Repository map

| Component | Ownership |
| --- | --- |
| `src/main.c` | Run orchestration and cleanup only |
| `src/bof_cli.c/.h` | CLI parsing, BOF argument packing, input files, SHA-256 |
| `src/json_output.c/.h` | All JSON escaping and schema-v2 serialization |
| `src/crash_guard.c/.h` | VEH state, context restoration, native fault details |
| `src/coffloader.c/.h` | COFF validation, relocation, imports, protections, unwind tables |
| `src/beacon_compat.c/.h` | Beacon compatibility APIs, output, and trace collection |
| `boftest.py` | Child-process automation and test-spec evaluation |
| `test/` | Source fixtures and regression suite |

Keep module responsibilities intact. Do not move JSON formatting back into
the loader core or expose crash-guard globals to `src/main.c`.

## Standard agent workflow

### 1. Establish a clean baseline

From an x64 Visual Studio Developer environment:

```powershell
nmake clean
nmake test
```

`x86_64-w64-mingw32-gcc` must be on `PATH`. On this lab image it is commonly
available under `C:\msys64\mingw64\bin`.

Do not continue from a failing baseline without identifying whether the
failure predates the requested change.

### 2. Inspect the target BOF

```powershell
.\dist\coffloader.exe --inspect go .\path\target.x64.o
```

Require:

- `status` equals `ok`;
- `phase` equals `inspect`;
- every required import is resolved;
- relocation, protection, and unwind metadata look plausible.

### 3. Execute through the JSON contract

```powershell
.\dist\coffloader.exe --json go .\path\target.x64.o i:0 Z:example
```

Execution passes only when all of the following are true:

- process exit code is zero;
- top-level `status` is `completed`;
- every command has `status: "ok"`;
- `summary.ok` is `true`;
- crash and callback-error counts are zero.

Never turn a load, parse, resolve, protection, unwind, crash, callback, or
timeout failure into a passing result.

### 4. Prefer the Python driver for iteration

```powershell
python .\boftest.py --inspect .\path\target.x64.o
python .\boftest.py --json .\path\target.x64.o i:0
python .\boftest.py --spec .\tests.json
```

Correlate `run_id` and `artifact.sha256` with endpoint telemetry when iterating
on detection rules.

## Argument packing reference

| Syntax | Meaning |
| --- | --- |
| `i:<value>` | 32-bit integer |
| `s:<value>` | 16-bit integer |
| `z:<text>` | Length-prefixed ANSI string |
| `Z:<text>` | Length-prefixed UTF-16 string |
| `b:<hex>` | Length-prefixed binary bytes |
| `b:@<path>` | Length-prefixed file contents |

Stateful multi-command example:

```powershell
.\dist\coffloader.exe --json --multi go .\path\target.x64.o `
    i:0 -- i:2 Z:whoami -- i:3
```

## Loader invariants

- MSVC `__imp_` imports use pointer slots.
- MinGW bare function imports use executable near trampolines.
- Bare data imports remain data and must never become trampolines.
- Unsupported or out-of-range relocations fail closed with stable codes.
- COFF offsets, indexes, counts, and spans are validated before dereference.
- Relocation happens in writable memory; final executable pages are RX.
- `.pdata` entries are validated before `RtlAddFunctionTable`.
- Every registered function table is deleted before image release.
- The VEH intercepts only selected recoverable hardware faults.
- Software exceptions continue to frame-based RPC, C++/CLR, and BOF handlers.
- Stack overflow is not treated as safely recoverable.
- JSON is escaped, machine-parseable, and identifies `coffloader/v2` with
  numeric `schema_version: 2`.

## Change routing

- CLI syntax or packing change: edit `src/bof_cli.*` and add packing regressions.
- JSON field or error-envelope change: edit `src/json_output.*`, retain compatible
  fields when possible, and update schema assertions/documentation.
- Fault classification or recovery change: edit `src/crash_guard.*` and test both
  hardware and software exception paths.
- COFF parsing, imports, relocations, memory, or unwind change: edit
  `src/coffloader.*` and add malformed-object coverage.
- Beacon API behavior change: edit `src/beacon_compat.*`, test output and trace
  behavior, and document whether the API is implemented, partial, or stubbed.
- Python pass/fail semantics: edit `boftest.py` and ensure failures cannot
  false-pass.

An MCP server should be a separate thin adapter that launches
`dist\coffloader.exe` as a child process, validates schema-v2 JSON, applies a
timeout, and restricts input paths. Never execute BOF code inside the MCP
server process.

## Regression expectations

Any loader, resolver, argument, JSON, crash, or compatibility change must add
or update a regression in `test/test_regressions.py`. Maintain coverage for:

- MSVC BOFs and `.pdata` unwind registration
- MinGW bare functions and bare data
- software exceptions caught by a BOF SEH frame
- selected hardware-fault capture and detailed JSON
- unresolved imports
- malformed and truncated objects
- invalid relocation and unwind records
- mixed packed multi-command execution
- callback errors that cannot false-pass
- inspect mode and schema-version fields

Fixtures are generated from source by `nmake test` and ignored by Git. Do not
commit generated `.x64.o`, `.obj`, `.dll`, `.lib`, `.exp`, PDB, or `dist`
artifacts.

## Required verification

Run the complete suite:

```powershell
nmake clean
nmake test
```

Run the strict syntax/warning review:

```powershell
cl /nologo /W4 /Zs `
    src\main.c src\bof_cli.c src\json_output.c src\crash_guard.c `
    src\coffloader.c src\beacon_compat.c
```

Existing compatibility warnings may remain, but a change must not introduce a
new warning category without documenting and justifying it.

Also perform direct checks for:

```powershell
.\dist\coffloader.exe --inspect go .\test\software_exception.x64.o
.\dist\coffloader.exe --json go .\test\crashtest.x64.o i:0
.\dist\coffloader.exe --json go .\test\crashtest.x64.o i:1
.\dist\coffloader.exe --json go .\test\badimport.x64.o
```

Parse each JSON response; do not validate it by visual inspection alone.

## Definition of done

- `nmake clean` followed by `nmake test` passes.
- The `/W4 /Zs` review introduces no new warning category.
- Inspect, success, deliberate crash, callback error, and unresolved-import
  responses parse as valid schema-v2 JSON.
- New failure paths return a stable phase, error code, and useful message.
- Documentation and module ownership reflect the change.
- Generated build artifacts remain untracked.
