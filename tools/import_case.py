import sys
import shutil
from pathlib import Path

def main():
    if len(sys.argv) < 3:
        print("Usage: python tools/import_case.py <case_id> <path_to_mem>")
        return 2
    case_id = sys.argv[1]
    src = Path(sys.argv[2]).expanduser().resolve()
    if not src.exists() or not src.is_file():
        print(f"ERROR: file not found: {src}")
        return 2

    root = Path(__file__).resolve().parent.parent
    case_dir = root / "data" / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    dst = case_dir / "memory.img"
    shutil.copy2(str(src), str(dst))
    print(f"Imported to {dst}")
    print("Now run: python -c \"from backend.app import _analyze_case; _analyze_case('%s')\"" % case_id)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
