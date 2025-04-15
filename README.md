# pa-permission-consistency-checker
Verifies that permissions granted across different systems (e.g., database, file system, cloud) are consistent for the same user or role. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-consistency-checker`

## Usage
`./pa-permission-consistency-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `--user`: The user to check permissions for.  If omitted, script runs with the effective user ID.
- `--path`: The path to check permissions recursively from. Defaults to current directory.
- `--exclude-file`: Path to a file containing file patterns to exclude. Each pattern should be on a new line.
- `--expected-mode`: The expected file mode (e.g., 
- `--report-inconsistencies`: Report files with inconsistent permissions.  If not specified, a summary is provided.
- `--fix-permissions`: Attempt to fix inconsistent permissions.  Requires appropriate privileges.
- `--recursive`: Check permissions recursively.  Enabled by default if path is a directory.
- `--debug`: Enable debug logging.

## License
Copyright (c) ShadowStrikeHQ
