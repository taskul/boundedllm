"""Documentation that does not run is documentation that is wrong.

The quickstart is the first thing a new integrator copies. If it drifts from the
API, their first five minutes end in a traceback and they close the tab. This
executes it exactly as written.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]


def quickstart_blocks() -> list[str]:
    text = (ROOT / "QUICKSTART.md").read_text(encoding="utf-8")
    return re.findall(r"```python\n(.*?)```", text, re.S)


def test_the_quickstart_example_runs_exactly_as_printed(tmp_path):
    runnable = [b for b in quickstart_blocks() if "asyncio.run(guard.chat" in b]
    assert runnable, "the quickstart no longer contains a self-contained example"

    script = tmp_path / "quickstart.py"
    script.write_text(
        f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r})\n" + runnable[0], encoding="utf-8"
    )
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"quickstart failed:\n{result.stderr[-2000:]}"
    # It has to actually produce an answer, not just import cleanly.
    assert "OK" in result.stdout and "deductible" in result.stdout.lower()


def test_the_quickstart_does_not_teach_a_pattern_the_package_rejects():
    """Guard against an example that would fail the moment it met real settings."""
    joined = "\n".join(quickstart_blocks())
    assert "Guard.from_settings" not in joined, "removed API still shown in the quickstart"
    assert "SQLStore(settings, audit)" in joined, "the batteries-included path is undocumented"
    # Every port the engine requires should appear, or a reader wires a broken Guard.
    for required in ("provider=", "signer=", "ledger=", "quotas=", "operations="):
        assert required in joined, f"quickstart omits the required {required} argument"


def test_referenced_documents_exist():
    """A broken link in the onboarding path is a dead end for a new reader."""
    text = (ROOT / "QUICKSTART.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\((?!https?:)([^)#]+)\)", text):
        assert (ROOT / target).exists(), f"QUICKSTART.md links to missing {target}"


def test_the_version_is_declared_in_exactly_one_place():
    """A version that drifts mislabels telemetry, wheels, and release notes.

    telemetry.py reported 0.2.0 for two releases because it was a literal. Any
    new hardcoded version string should fail here rather than ship.
    """
    import re
    import tomllib

    import boundedllm

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == boundedllm.__version__

    # The changelog must have an entry for whatever the package claims to be.
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{boundedllm.__version__}]" in changelog, "no changelog entry for this version"

    # No other source file may restate it.
    pattern = re.compile(r'"\d+\.\d+\.\d+"')
    for path in (ROOT / "src").rglob("*.py"):
        if path.name == "__init__.py" and path.parent.name == "boundedllm":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line) and "version" in line.lower():
                raise AssertionError(
                    f"hardcoded version at {path.relative_to(ROOT)}:{number}: {line.strip()}"
                )
