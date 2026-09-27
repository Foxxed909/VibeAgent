"""Legacy handler — disabled.

All traffic is handled by api/index.py (ASGI app).
Kept as a thin re-export so older docs don't 404 during transition.
"""
# Not a Vercel entrypoint (no BaseHTTPRequestHandler named handler).
from api.index import app  # noqa: F401
