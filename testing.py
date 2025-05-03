from typing import List, Tuple, Optional
from datetime import datetime
import glob

def parse_operations_string(operations_str: str) -> List[Tuple[str, str]]:
    """
    Parse a string of operations into a list of (operation, path) tuples.
    Each line contains a path followed by spaces and operations (r, w, rw, etc.).
    Only include 'read' or 'write' operations, ignoring other letters (e.g., 'm' in 'mr').
    """
    operations = []
    lines = operations_str.strip().splitlines()
    for line in lines:
        line = line.rstrip(',').strip()
        if not line:
            continue
        parts = line.rsplit(maxsplit=1)
        if len(parts) != 2:
            continue
        path, ops = parts
        for op in ops:
            if op == 'r':
                operations.append(('read', path))
            elif op == 'w':
                operations.append(('write', path))
    
    return operations

def process_file_operations(
    operations: List[Tuple[str, str]]
) -> List[Tuple[str, str, Optional[bool]]]:
    """
    For each (operation, path) pair:
      - if `path` contains '*' or '**', treat it as a glob pattern,
        use iglob() to find _one_ matching entry, test it, then break;
      - otherwise, try to open(path) in 'r' or 'w' and catch exceptions.

    Returns a list of (operation, concrete_path, status) where status is:
      - True   = able to open for read/write
      - False  = PermissionError
      - None   = FileNotFound / IsADirectoryError / any other
    """
    report: List[Tuple[str, str, Optional[bool]]] = []

    for operation, path in operations:
        if operation not in ('read', 'write'):
            continue

        mode = 'r' if operation == 'read' else 'w'

        if '*' in path:
            # choose recursive only if '**' is present
            recursive = '**' in path
            matched_any = False

            # iglob returns matches lazily, so it'll stop searching
            # as soon as we break out of this loop.
            for match in glob.iglob(path, recursive=recursive):
                matched_any = True
                try:
                    with open(match, mode):
                        report.append((operation, match, True))
                except PermissionError:
                    report.append((operation, match, False))
                except (FileNotFoundError, IsADirectoryError, OSError):
                    report.append((operation, match, None))
                # stop after the first match
                break

            if not matched_any:
                # no match found at all
                report.append((operation, path, None))

        else:
            # literal path
            try:
                with open(path, mode):
                    report.append((operation, path, True))
            except PermissionError:
                report.append((operation, path, False))
            except (FileNotFoundError, IsADirectoryError, OSError):
                report.append((operation, path, None))

    return report

def generate_report(report: List[Tuple[str, str, bool]], output_file: str = "tests/maaan/file_operation_report.txt") -> None:
    """
    Generate a text report from the processed operations and save it to a file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, 'w') as f:
        f.write(f"File Operation Report - Generated on {timestamp}\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Operation':<10} {'Path':<60} {'Status':<10}\n")
        f.write("-" * 80 + "\n")
        
        for operation, path, success in report:
            if success is None:
                status = "None"
            elif success:
                status = "Allowed"
            elif not success:
                status = "Denied"
            f.write(f"{operation:<10} {path:<60} {status:<10}\n")
    
    print(f"Report generated: {output_file}")

if __name__ == "__main__":
    with open("tests/maaan/man_flat_paths.txt", 'r') as f:
            operations_str = f.read()
            
    operations = parse_operations_string(operations_str)
    
    report = process_file_operations(operations)
    
    generate_report(report)