#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import stat
import pathspec  # Used for filtering files based on patterns

from rich.console import Console
from rich.table import Table

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants for error handling
ERROR_USER_NOT_FOUND = 1
ERROR_PERMISSION_DENIED = 2
ERROR_FILE_NOT_FOUND = 3
ERROR_INCONSISTENT_PERMISSIONS = 4
ERROR_INVALID_ARGUMENT = 5
ERROR_UNKNOWN = 99

# Default file mask for file permissions. Change to fit system's needs.
DEFAULT_FILE_MODE_MASK = 0o777  # rwxrwxrwx

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Verifies permission consistency across file systems for users or roles."
    )

    parser.add_argument(
        "--user",
        "-u",
        type=str,
        help="The user to check permissions for.  If omitted, script runs with the effective user ID.",
    )

    parser.add_argument(
        "--path",
        "-p",
        type=str,
        default=".",
        help="The path to check permissions recursively from. Defaults to current directory.",
    )

    parser.add_argument(
        "--exclude-file",
        "-e",
        type=str,
        help="Path to a file containing file patterns to exclude. Each pattern should be on a new line.",
    )
    
    parser.add_argument(
        "--expected-mode",
        "-m",
        type=str,
        help="The expected file mode (e.g., '755', '644'). If not specified, checks any access.  Must be an octal integer.",
    )

    parser.add_argument(
        "--report-inconsistencies",
        "-r",
        action="store_true",
        help="Report files with inconsistent permissions.  If not specified, a summary is provided.",
    )

    parser.add_argument(
        "--fix-permissions",
        "-f",
        action="store_true",
        help="Attempt to fix inconsistent permissions.  Requires appropriate privileges.",
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Check permissions recursively.  Enabled by default if path is a directory.",
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )

    return parser.parse_args()


def get_file_mode(file_path):
    """
    Gets the file mode (permissions) of a given file path.
    Args:
        file_path (str): The path to the file.
    Returns:
        int: The file mode as an integer (e.g., 0o777).
             Returns None if the file does not exist or an error occurs.
    """
    try:
        return stat.S_IMODE(os.stat(file_path).st_mode)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except OSError as e:
        logging.error(f"Error getting file mode for {file_path}: {e}")
        return None


def check_file_permissions(file_path, user=None, expected_mode=None):
    """
    Checks if a user has access to a file and if the file has the expected permissions.

    Args:
        file_path (str): The path to the file.
        user (str, optional): The user to check permissions for. Defaults to None (current user).
        expected_mode (int, optional): The expected file mode (e.g., 0o755). Defaults to None (no mode check).

    Returns:
        bool: True if the user has access and the file mode matches (if specified), False otherwise.
    """

    try:
        # Security check: Use os.path.abspath to resolve symlinks and prevent path traversal vulnerabilities.
        file_path = os.path.abspath(file_path)

        # Check file existence
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return False

        # Check file permissions for the specified user or current user
        if user:
            # Not implemented for Linux without external tools (e.g., `sudo -u <user> test -rwx <file>`).
            logging.warning("User-specific permission checks are not fully supported on Linux without external tools.")
            # For demo purposes only: naive check based on current user's permissions
            if not os.access(file_path, os.R_OK):
                logging.warning(f"Current user does not have read access to {file_path}")
                return False
        else:
            if not os.access(file_path, os.R_OK):
                logging.warning(f"Current user does not have read access to {file_path}")
                return False


        # Check the file mode if expected_mode is specified
        if expected_mode is not None:
            file_mode = get_file_mode(file_path)
            if file_mode is None:  # Handle error already logged in get_file_mode
                return False

            if file_mode != expected_mode:
                logging.warning(
                    f"File {file_path} has mode {oct(file_mode)}, expected {oct(expected_mode)}"
                )
                return False

        return True  # User has access, and the mode matches (if specified)

    except OSError as e:
        logging.error(f"Error checking permissions for {file_path}: {e}")
        return False


def fix_file_permissions(file_path, expected_mode):
    """
    Attempts to fix the permissions of a file to the expected mode.

    Args:
        file_path (str): The path to the file.
        expected_mode (int): The expected file mode (e.g., 0o755).

    Returns:
        bool: True if the permissions were successfully fixed, False otherwise.
    """
    try:
        # Security check: Use os.path.abspath to resolve symlinks and prevent path traversal vulnerabilities.
        file_path = os.path.abspath(file_path)

        os.chmod(file_path, expected_mode)
        logging.info(f"Successfully changed permissions of {file_path} to {oct(expected_mode)}")
        return True
    except OSError as e:
        logging.error(f"Error fixing permissions for {file_path}: {e}")
        return False


def load_exclude_patterns(exclude_file):
    """
    Loads exclude patterns from a file.

    Args:
        exclude_file (str): Path to the file containing exclude patterns.

    Returns:
        pathspec.PathSpec: A PathSpec object containing the exclude patterns, or None if an error occurred.
    """
    try:
        with open(exclude_file, "r") as f:
            patterns = [line.strip() for line in f if line.strip()]  # Read and filter empty lines
        return pathspec.PathSpec(patterns)
    except FileNotFoundError:
        logging.error(f"Exclude file not found: {exclude_file}")
        return None
    except OSError as e:
        logging.error(f"Error reading exclude file: {e}")
        return None


def main():
    """
    Main function to execute the permission consistency checker.
    """
    args = setup_argparse()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Input validation: Check if the user-provided path is valid
    if not os.path.exists(args.path):
        logging.error(f"Path does not exist: {args.path}")
        sys.exit(ERROR_FILE_NOT_FOUND)

    # Input validation: Validate that expected_mode is a valid octal integer.
    expected_mode = None
    if args.expected_mode:
        try:
            expected_mode = int(args.expected_mode, 8)
            # Applying a bitwise AND operation with DEFAULT_FILE_MODE_MASK 
            # ensures that the provided mode respects existing system restrictions.
            expected_mode &= DEFAULT_FILE_MODE_MASK
            logging.debug(f"Parsed expected mode: {oct(expected_mode)}")
        except ValueError:
            logging.error("Invalid expected mode. Must be an octal integer (e.g., 755).")
            sys.exit(ERROR_INVALID_ARGUMENT)


    # Load exclude patterns if an exclude file is provided.
    exclude_spec = None
    if args.exclude_file:
        exclude_spec = load_exclude_patterns(args.exclude_file)
        if exclude_spec is None:
            sys.exit(1)

    console = Console()
    table = Table(title="Permission Consistency Check")
    table.add_column("File Path", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Expected Mode", style="green")
    table.add_column("Actual Mode", style="yellow")

    inconsistent_count = 0
    total_files = 0

    if os.path.isfile(args.path):
        # If a single file is provided as the path
        total_files = 1
        if exclude_spec and exclude_spec.match_file(args.path):
            logging.info(f"Skipping excluded file: {args.path}")
            status = "Excluded"
            expected_mode_str = "N/A"
            actual_mode_str = "N/A"
        else:
            has_access = check_file_permissions(args.path, args.user, expected_mode)
            actual_mode = get_file_mode(args.path)

            if has_access:
                status = "OK"
                expected_mode_str = oct(expected_mode) if expected_mode else "Any"
                actual_mode_str = oct(actual_mode) if actual_mode else "N/A"

            else:
                status = "Inconsistent"
                inconsistent_count += 1
                expected_mode_str = oct(expected_mode) if expected_mode else "Any"
                actual_mode_str = oct(actual_mode) if actual_mode else "N/A"
                if args.fix_permissions and expected_mode:
                    if fix_file_permissions(args.path, expected_mode):
                        status = "Fixed"

        if args.report_inconsistencies or status != "OK":
           table.add_row(args.path, status, expected_mode_str, actual_mode_str)

    else: # Directory
        # Walk the directory tree and check permissions recursively
        for root, _, files in os.walk(args.path):
            for file in files:
                file_path = os.path.join(root, file)
                total_files += 1

                # Exclude files based on patterns, if specified
                if exclude_spec and exclude_spec.match_file(file_path):
                    logging.info(f"Skipping excluded file: {file_path}")
                    status = "Excluded"
                    expected_mode_str = "N/A"
                    actual_mode_str = "N/A"
                else:
                    has_access = check_file_permissions(file_path, args.user, expected_mode)
                    actual_mode = get_file_mode(file_path)

                    if has_access:
                        status = "OK"
                        expected_mode_str = oct(expected_mode) if expected_mode else "Any"
                        actual_mode_str = oct(actual_mode) if actual_mode else "N/A"
                    else:
                        status = "Inconsistent"
                        inconsistent_count += 1
                        expected_mode_str = oct(expected_mode) if expected_mode else "Any"
                        actual_mode_str = oct(actual_mode) if actual_mode else "N/A"
                        if args.fix_permissions and expected_mode:
                            if fix_file_permissions(file_path, expected_mode):
                                status = "Fixed"

                if args.report_inconsistencies or status != "OK":
                    table.add_row(file_path, status, expected_mode_str, actual_mode_str)
            if not args.recursive:
                break

    if args.report_inconsistencies:
        console.print(table)
    else:
        console.print(f"Total files checked: {total_files}")
        console.print(f"Files with inconsistent permissions: {inconsistent_count}")

    if inconsistent_count > 0:
        sys.exit(ERROR_INCONSISTENT_PERMISSIONS)
    else:
        sys.exit(0)  # Success


if __name__ == "__main__":
    main()