"""Start the CallGuard website.

Run it with:  uv run scripts/serve.py
Then open http://localhost:8000 in your browser. Press Control+C here to stop it.
It only listens on this Mac (127.0.0.1), so other computers on your network can't reach it.
"""

import uvicorn

if __name__ == "__main__":
    print("CallGuard is starting at http://localhost:8000  (Control+C to stop)", flush=True)
    uvicorn.run("callguard.web:app", host="127.0.0.1", port=8000, log_level="warning")
