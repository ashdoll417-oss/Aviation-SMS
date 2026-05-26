import os
import sys
import glob
import json
import traceback
from datetime import datetime

"""
Best-effort local helper to extract the exact Python traceback for the last /dashboard 500.

Because this environment can't directly access your Vercel runtime console history,
this script searches locally for common log files / traces and prints:
- any stack trace it finds
- guidance on where to look in Vercel to retrieve the traceback (file + line number)
"""


def _read_text_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _looks_like_traceback(text: str) -> bool:
    lowered = (text or "").lower()
    return ("traceback (most recent call last)" in lowered) or ("modulenotfounderror" in lowered) or ("sqlalchemy" in lowered)


def _find_tracebacks_in_files(patterns):
    hits = []
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            text = _read_text_file(path)
            if _looks_like_traceback(text) or ("/dashboard" in text):
                hits.append((path, text))
    return hits


def main():
    # Optional environment hints
    vercel_project = os.environ.get("VERCEL_PROJECT", "")
    vercel_env = os.environ.get("VERCEL_ENV", "")
    print("=== scripts/check_vercel_logs.py ===")
    print(f"Time: {datetime.utcnow().isoformat()}Z")
    if vercel_project:
        print(f"VERCEL_PROJECT: {vercel_project}")
    if vercel_env:
        print(f"VERCEL_ENV: {vercel_env}")
    print()

    # Search for likely local traces (dev/prod) if they exist in this repo.
    # Add/remove patterns as needed for your deployment/logging setup.
    patterns = [
        "instance/**/*.log",
        "logs/**/*.log",
        "migrations/**/error*.txt",
        "**/*vercel*.log",
        "**/*error*.log",
        "**/*traceback*.txt",
        "**/*stack*.txt",
    ]

    hits = _find_tracebacks_in_files(patterns)

    if hits:
        print(f"Found {len(hits)} candidate local log/trace files containing traceback-like text.")
        print()
        for idx, (path, text) in enumerate(hits, start=1):
            print(f"--- Hit {idx}: {path} ---")
            # Try to print only the tail portion where the exception is most likely.
            tail = text[-12000:] if len(text) > 12000 else text
            print(tail.strip())
            print()
            # stop after first major hit to keep it quick
            break
    else:
        print("No local log files with traceback text were found by this script.")
        print()
        print("Next best step: extract the traceback directly from Vercel:")
        print("1) Vercel Dashboard -> Project -> Deployments -> select the deployment showing the 500")
        print("2) Open 'Logs' (or 'Function Logs' depending on UI)")
        print("3) Find the entry for GET /dashboard that took ~8000ms")
        print("4) Copy/paste the full 'Traceback (most recent call last)' section including:")
        print("   - the Python file path")
        print("   - the exact line number")
        print("   - the exception type (e.g., KeyError, OperationalError, ProgrammingError, etc.)")
        print()
        print("If you paste that traceback here, I can pinpoint the exact failing line and propose a targeted fix.")

    print("=== End ===")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Script failed while searching logs:")
        print(traceback.format_exc())
        sys.exit(1)
