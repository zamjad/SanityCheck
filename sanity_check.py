# sanity_check.py
#
# Usage
# python sanity_check.py capture --dir /path/to/dir --output output.json --verbose
# Copy the new build files
# python sanity_check.py compare --dir /path/to/dir --input output.json --diffout diff.json --verbose --delete
# Display the differences

import json
import argparse
import fnmatch
import logging
from pathlib import Path
from typing import List, Dict, Set
from hashlib import sha256

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

def file_matches_patterns(filename: str, includes: List[str], excludes: List[str]) -> bool:
    """
    Returns True if 'filename' matches one of the 'includes' patterns
    (or if no include patterns are specified, we use a default),
    and does NOT match any 'excludes' patterns.
    """
    # Default include patterns
    if not includes:
        includes = ["*.dll", "*.exe"]

    # Check if the file matches at least one 'include' pattern
    if not any(fnmatch.fnmatch(filename, pattern) for pattern in includes):
        return False

    # Check if the file matches any 'exclude' pattern
    if any(fnmatch.fnmatch(filename, pattern) for pattern in excludes):
        return False

    return True

def compute_file_hash(file_path: Path) -> str:
    """
    Compute the SHA256 hash of a file.
    """
    hasher = sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def scan_directory(directory: Path, includes: List[str], excludes: List[str], recursive: bool = False, verbose: bool = False) -> Dict[str, Dict]:
    """
    Scan the directory for files matching include/exclude patterns
    and return a dictionary of file info.
    """
    data = {}
    if recursive:
        file_iterator = directory.rglob("*")
    else:
        file_iterator = directory.iterdir()

    for entry in file_iterator:
        if entry.is_file():
            if file_matches_patterns(entry.name, includes, excludes):
                if verbose:
                    logger.info(f"Processing file: {entry}")
                file_info = {
                    "size": entry.stat().st_size,
                    "last_modified": entry.stat().st_mtime,
                    "hash": compute_file_hash(entry),
                }
                data[str(entry.relative_to(directory))] = file_info
    return data

def capture_files(directory: Path, output_file: Path, includes: List[str], excludes: List[str], recursive: bool = False, verbose: bool = False):
    """
    Scan the directory for files matching include/exclude patterns,
    capture basic info (size, last modified time, hash),
    and store in a JSON file.
    """
    try:
        data = scan_directory(directory, includes, excludes, recursive, verbose)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Captured info for {len(data)} files in '{directory}'.")
        logger.info(f"Data saved to '{output_file}'.")
    except Exception as e:
        logger.error(f"Error capturing files: {e}")

def load_old_data(input_file: Path) -> Dict:
    """
    Load previously captured data from the input file.
    """
    if not input_file.exists():
        raise FileNotFoundError(f"Cannot find previous data file '{input_file}' to compare.")

    with open(input_file, "r") as f:
        return json.load(f)

def compare_file_sets(old_files: Set[str], new_files: Set[str]) -> tuple:
    """
    Compare sets of old and new files to identify added, removed, and common files.
    """
    removed_files = sorted(old_files - new_files)
    added_files = sorted(new_files - old_files)
    common_files = old_files.intersection(new_files)
    return removed_files, added_files, common_files

def compare_file_details(old_data: Dict, new_data: Dict, common_files: List[str]) -> List[str]:
    """
    Compare details (size, modification time, hash) of common files 
    to identify modified files.
    """
    changed_files = []
    for file_name in common_files:
        old_info = old_data[file_name]
        new_info = new_data[file_name]
        if (old_info["size"] != new_info["size"]) or \
           (old_info["last_modified"] != new_info["last_modified"]) or \
           (old_info["hash"] != new_info["hash"]):
            changed_files.append(file_name)
    return sorted(changed_files)

def write_diff_output(diff_output: Path, diff_result: Dict):
    """
    Write the comparison results to the output JSON file.
    """
    with open(diff_output, "w") as f:
        json.dump(diff_result, f, indent=2)
    logger.info(f"Differences written to '{diff_output}'.")

def print_diff_summary(removed_files: List[str], added_files: List[str], changed_files: List[str]):
    """
    Print the comparison results to the console.
    """
    if not removed_files and not added_files and not changed_files:
        logger.info("No differences found. All specified files are unchanged.")
    else:
        if removed_files:
            logger.info("Removed files:")
            for f_ in removed_files:
                logger.info(f"  - {f_}")

        if added_files:
            logger.info("Added files:")
            for f_ in added_files:
                logger.info(f"  + {f_}")

        if changed_files:
            logger.info("Modified files:")
            for f_ in changed_files:
                logger.info(f"  * {f_}")

def compare_files(directory: Path, input_file: Path, diff_output: Path, includes: List[str], excludes: List[str], recursive: bool = False, delete: bool = False, verbose: bool = False):
    """
    Scan the directory for files matching include/exclude patterns
    and compare current data with previously captured data.
    """
    try:
        # Load old data
        old_data = load_old_data(input_file)

        # Gather new data
        new_data = scan_directory(directory, includes, excludes, recursive, verbose)

        # Compare file sets
        removed_files, added_files, common_files = compare_file_sets(set(old_data.keys()), set(new_data.keys()))

        # Compare file details
        changed_files = compare_file_details(old_data, new_data, common_files)

        # Prepare the difference result
        diff_result = {
            "removed_files": removed_files,
            "added_files": added_files,
            "modified_files": changed_files,
            "summary": {
                "total_removed": len(removed_files),
                "total_added": len(added_files),
                "total_modified": len(changed_files),
            }
        }

        # Write differences to the specified JSON file
        write_diff_output(diff_output, diff_result)

        # Print results to the console
        print_diff_summary(removed_files, added_files, changed_files)

        # Delete the input file if requested
        if delete:
            input_file.unlink()
            logger.info(f"Deleted input file '{input_file}'.")

    except Exception as e:
        logger.error(f"Error comparing files: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Quickly capture and compare files in a folder (DLL/EXE by default) with include/exclude filters."
    )
    subparsers = parser.add_subparsers(dest="mode", help="Choose capture, compare or help mode.")

    # Capture subcommand
    capture_parser = subparsers.add_parser("capture", help="Capture file info (pre-build).")
    capture_parser.add_argument("-d", "--dir", required=True, type=Path, help="Directory to scan for files.")
    capture_parser.add_argument("-o", "--output", required=True, type=Path, help="JSON file to save captured data.")
    capture_parser.add_argument("-i", "--include", nargs="*", default=["*.dll", "*.exe"],
                                help="Patterns of files to include (e.g. '*.dll' '*.exe'). Defaults to ['*.dll','*.exe'].")
    capture_parser.add_argument("-e", "--exclude", nargs="*", default=[],
                                help="Patterns of files to exclude (e.g. '*Test.dll').")
    capture_parser.add_argument("-r", "--recursive", action="store_true", help="Scan directories recursively.")
    capture_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    # Compare subcommand
    compare_parser = subparsers.add_parser("compare", help="Compare file info (post-build).")
    compare_parser.add_argument("-d", "--dir", required=True, type=Path, help="Directory to scan for files.")
    compare_parser.add_argument("-i", "--input", required=True, type=Path, help="JSON file with previously captured data.")
    compare_parser.add_argument("-f", "--diffout", required=True, type=Path, help="JSON file to save the difference report.")
    compare_parser.add_argument("-n", "--include", nargs="*", default=["*.dll", "*.exe"],
                                help="Patterns of files to include (e.g. '*.dll' '*.exe'). Defaults to ['*.dll','*.exe'].")
    compare_parser.add_argument("-e", "--exclude", nargs="*", default=[],
                                help="Patterns of files to exclude (e.g. '*Test.dll').")
    compare_parser.add_argument("-r", "--recursive", action="store_true", help="Scan directories recursively.")
    compare_parser.add_argument("-l", "--delete", action="store_true", help="Delete the input file after comparison.")
    compare_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    subparsers.add_parser("help", help="Display help (same as -h or --help)")
    args = parser.parse_args()

    if args.mode == "capture":
        capture_files(args.dir, args.output, args.include, args.exclude, args.recursive, args.verbose)
    elif args.mode == "compare":
        compare_files(args.dir, args.input, args.diffout, args.include, args.exclude, args.recursive, args.delete, args.verbose)
    elif args.mode == "help":
        parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
