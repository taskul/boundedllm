"""Concrete implementations of the core ports and provider contracts.

Everything here is optional. The core depends on ``agentguard.ports``; these
modules depend on SQLAlchemy, httpx, and deployment configuration, which is why
they are kept off the core import path.
"""
