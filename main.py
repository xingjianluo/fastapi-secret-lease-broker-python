"""Local entry point: ``python main.py`` serves the broker on 127.0.0.1:8000."""

from __future__ import annotations

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.app:app", host="127.0.0.1", port=8000, reload=False)
