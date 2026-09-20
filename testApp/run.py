"""Development entry point that selects testApp's isolated Python environment."""

import subprocess
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
LOCAL_PYTHON = APP_ROOT / ".venv" / "Scripts" / "python.exe"


def _use_testapp_interpreter() -> None:
    """Restart under testApp/.venv when a parent virtual environment is active.

    This keeps `python run.py` convenient even when the repository's separate
    library environment is activated. All arguments are preserved across the
    restart, and the API key remains loaded later from testApp/.env.
    """
    if not LOCAL_PYTHON.exists():
        return
    current = Path(sys.executable).resolve()
    target = LOCAL_PYTHON.resolve()
    if current != target:
        # The interpreter and script are fixed local paths. Passing an argument
        # list with shell=False preserves spaces in Windows project paths.
        completed = subprocess.run(  # noqa: S603
            [str(target), str(Path(__file__).resolve()), *sys.argv[1:]],
            cwd=APP_ROOT,
            check=False,
        )
        raise SystemExit(completed.returncode)


def main() -> None:
    _use_testapp_interpreter()
    if "--check" in sys.argv:
        # Importing the app catches missing runtime dependencies without opening
        # a port, reading customer requests, or calling the model provider.
        from roadshield.main import create_app  # noqa: F401

        print(f"RoadShield runtime ready: {sys.executable}")
        return

    import uvicorn

    uvicorn.run("roadshield.main:create_app", factory=True, host="127.0.0.1", port=8010, reload=False)


if __name__ == "__main__":
    main()
