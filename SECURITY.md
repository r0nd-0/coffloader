# Security Policy

## Scope

COFFLoader executes arbitrary native BOF code with the privileges of the
calling process. It is a research and debugging harness, not a sandbox or a
security boundary.

Security reports should focus on vulnerabilities in the loader itself, such
as malformed-COFF memory corruption, unsafe import resolution, protection
errors, incorrect validation, or failures that escape the documented process
boundary.

Expected behavior includes:

- BOF code accessing the caller's files, registry, network, tokens, and APIs;
- the process terminating on faults that cannot be recovered safely;
- provider DLL loading during import resolution, including `--inspect`;
- state corruption after a recovered native fault.

## Reporting

Please use GitHub's private security-advisory feature for the repository rather
than opening a public issue with exploit details. Include the affected commit,
Windows version, compiler, minimal object or reproduction steps, observed JSON
or exit code, and the expected behavior.

Do not include production credentials, real target data, or sensitive endpoint
telemetry in a report.
