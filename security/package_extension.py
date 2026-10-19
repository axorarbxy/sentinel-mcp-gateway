"""Package the browser extension with a named top-level folder in the ZIP."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXTENSION_ROOT = PROJECT_ROOT / "security" / "extension"
OUTPUT_PATH = PROJECT_ROOT / "frontend" / "public" / "sentinel-extension.zip"
ARCHIVE_FOLDER = "sentinel-mcp-extension"


def main() -> None:
    with ZipFile(OUTPUT_PATH, "w", compression=ZIP_DEFLATED) as archive:
        for path in sorted(EXTENSION_ROOT.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                archive_name = Path(ARCHIVE_FOLDER) / path.relative_to(EXTENSION_ROOT)
                archive.write(path, archive_name.as_posix())


if __name__ == "__main__":
    main()
