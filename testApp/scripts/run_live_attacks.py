"""Run every bounded RoadShield attack through the configured live model.

Run it from the testApp directory::

    .venv/Scripts/python.exe scripts/run_live_attacks.py

A note on what this proves. Most scenarios come back OK against a real model,
because the model itself declines the attack and the answer is harmless. That is
a good outcome and it is *not* a test of this package: the guard's controls never
had to fire. The deterministic simulator in ``roadshield.agent`` is what exercises
them, by producing exactly the malicious output a compromised model would. Run
both, and read a live OK as "the model behaved", not "the boundary held".
"""

import sys
from pathlib import Path

# Importable when invoked as a script, not only as a module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from roadshield.attacks import CASES
from roadshield.main import create_app

ORIGIN = "http://127.0.0.1:8010"


def main() -> None:
    """Print security outcomes without printing prompts, model answers, or secrets."""
    failures = []
    with TestClient(create_app()) as client:
        login = client.post(
            "/api/auth/login",
            headers={"Origin": ORIGIN},
            json={
                "tenant_id": "roadshield-midwest",
                "email": "alice@roadshield.test",
                "password": "Demo-Alice-2026!",
            },
        )
        login.raise_for_status()
        csrf = client.cookies["roadshield_csrf"]
        headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
        provider = client.get("/api/agent/status").json()["provider"]
        if not provider.startswith("Claude"):
            raise RuntimeError("ANTHROPIC_API_KEY was not loaded; refusing to label this a live run")
        print(f"Provider: {provider}")
        for name in CASES:
            response = client.post(f"/api/attacks/{name}", headers=headers, json={})
            if response.status_code != 200:
                failures.append(f"{name}: HTTP {response.status_code}")
                print(f"FAIL {name}: HTTP {response.status_code}")
                continue
            result = response.json()
            marker = "PASS" if result["protected"] else "FAIL"
            # "guard" means a deterministic control stopped it; "model" means the
            # model simply did not comply and nothing needed to be enforced.
            enforced = "guard" if result["actual"] in {"BLOCKED", "DENIED"} else "model"
            print(f"{marker} {name}: {result['actual']} (stopped by: {enforced})")
            if not result["protected"]:
                failures.append(f"{name}: boundary failed")
    if failures:
        raise SystemExit("Live attack failures: " + "; ".join(failures))


if __name__ == "__main__":
    main()
