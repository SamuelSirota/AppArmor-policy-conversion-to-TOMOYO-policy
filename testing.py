from typing import List, Tuple, Optional
from datetime import datetime
import glob, os

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
      - True   = able to read/write
      - False  = PermissionError
      - None   = FileNotFoundError / OSError
    """
    report: List[Tuple[str, str, Optional[bool]]] = []

    def test_path(operation: str, path: str) -> Tuple[str, str, Optional[bool]]:
        mode = 'r' if operation == 'read' else 'w'
        try:
            with open(path, mode):
                return (operation, path, True)
        except PermissionError:
            return (operation, path, False)
        except IsADirectoryError:
            try:
                if operation == 'read':
                    _ = os.listdir(path)
                else:  # write
                    test_file = os.path.join(path, ".tmp_test_write")
                    with open(test_file, 'w') as f:
                        f.write("test")
                    os.remove(test_file)
                return (operation, path, True)
            except PermissionError:
                return (operation, path, False)
            except (FileNotFoundError, OSError):
                return (operation, path, None)
        except (FileNotFoundError, OSError):
            return (operation, path, None)

    for operation, path in operations:
        if operation not in ('read', 'write'):
            continue

        if '*' in path:
            recursive = '**' in path
            matched_any = False
            for match in glob.iglob(path, recursive=recursive):
                matched_any = True
                report.append(test_path(operation, match))
                break  # only first match
            if not matched_any:
                report.append((operation, path, None))
        else:
            report.append(test_path(operation, path))

    return report

def generate_report(allow_report: List[Tuple[str, str, bool]], deny_report: List[Tuple[str, str, bool]], output_file: str = "tests/maaan/file_operation_report.txt") -> None:
    """
    Generate a text report from the processed operations and save it to a file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, 'w') as f:
        f.write(f"File Operation Report - Generated on {timestamp}\n")
        f.write("-" * 80 + "\n")
        f.write("Allowed Operations:\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Operation':<10} {'Path':<60} {'Status':<10}\n")
        f.write("-" * 80 + "\n")
        
        for operation, path, success in allow_report:
            if success is None:
                status = "None"
            elif success:
                status = "Allowed"
            elif not success:
                status = "Denied"
            f.write(f"{operation:<10} {path:<60} {status:<10}\n")
            
        f.write("-" * 80 + "\n")
        f.write("\nDenied Operations:\n")
        f.write("-" * 80 + "\n")
        
        for operation, path, success in deny_report:
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
    with open("tests/maaan/deny_flat_paths.txt", 'r') as f:
            deny_operations_str = f.read()
            
    allowed_operations = parse_operations_string(operations_str)
    denied_operations = parse_operations_string(deny_operations_str)
    
    allowed_report = process_file_operations(allowed_operations)
    deny_report = process_file_operations(denied_operations)
    
    generate_report(allowed_report, deny_report)