import os
import sys
from pathlib import Path

# Add project directory to sys.path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

# Sub-path setting for reverse proxy / Passenger
if "DL_ROOT_PATH" not in os.environ:
    os.environ["DL_ROOT_PATH"] = "/dl"

# Import FastAPI app from main.py
from main import app

# cPanel Phusion Passenger requires a WSGI 'application' callable.
# a2wsgi adapts ASGI (FastAPI) to WSGI.
from a2wsgi import ASGIToWSGI

application = ASGIToWSGI(app)
