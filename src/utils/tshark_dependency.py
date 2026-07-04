import shutil
from pathlib import Path


MACOS_TSHARK_PATH = Path(
    "/Applications/Wireshark.app/Contents/MacOS/tshark"
)


def find_tshark() -> str | None:
    """
    Find tshark executable.

    Search order:
    1. System PATH
    2. Standard Wireshark installation path on macOS
    """

    tshark_path = shutil.which("tshark")

    if tshark_path:
        return tshark_path

    if MACOS_TSHARK_PATH.exists():
        return str(MACOS_TSHARK_PATH)

    return None


def is_tshark_available() -> bool:
    """
    Check whether tshark is available.
    """

    return find_tshark() is not None