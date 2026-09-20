"""Test configuration keeps the package importable from a source checkout."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

# Windows defaults to ProactorEventLoop, which psycopg's async driver refuses.
# Set at import so every loop the session creates is compatible; CI runs on Linux
# where the default is already fine. Without this the pgvector adapter tests fail
# on a Windows checkout and look like an adapter bug rather than a loop mismatch.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
