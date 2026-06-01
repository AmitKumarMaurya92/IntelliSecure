"""
InteliSecure - Application Launcher
=====================================
Run this from the project root:  python run.py
Or via uvicorn:                  uvicorn backend.app_old:app --reload

This launcher ensures the backend package imports work correctly.
"""

import uvicorn
import os
import sys

# Ensure backend directory is on path for package-level imports
ROOT_DIR    = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")

sys.path.insert(0, ROOT_DIR)

if __name__ == "__main__":
    uvicorn.run(
        "backend.app_old:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        reload_dirs=[BACKEND_DIR]
    )
