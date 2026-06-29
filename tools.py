# tools.py
# All 4 tool wrappers for the vulnerability finder agent
# Each tool is standalone — test them individually before wiring into the graph

import os
import re
import json
import tempfile
import subprocess
from pathlib import Path


# ── 1. GITHUB FETCHER ─────────────────────────────────────────────────────────
# Accepts a public GitHub URL, clones it to a temp directory, returns local path

def fetch_github_repo(url: str) -> dict:
    """
    Clone a public GitHub repo to a temp directory.
    Returns: { "path": str, "error": str | None }
    """
    # Basic URL validation
    pattern = r"https://github\.com/[\w.-]+/[\w.-]+"
    if not re.match(pattern, url):
        return {"path": None, "error": f"Invalid GitHub URL: {url}"}

    tmp_dir = tempfile.mkdtemp(prefix="vuln_scan_")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            return {"path": None, "error": f"Git clone failed: {result.stderr.strip()}"}

        return {"path": tmp_dir, "error": None}

    except subprocess.TimeoutExpired:
        return {"path": None, "error": "Git clone timed out after 60 seconds"}
    except FileNotFoundError:
        return {"path": None, "error": "Git is not installed or not in PATH"}


# ── 2. LOCAL DIRECTORY READER ─────────────────────────────────────────────────
# Validates a local path, walks the file tree, returns language summary

EXTENSION_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".java": "Java", ".go": "Go", ".rb": "Ruby", ".rs": "Rust",
    ".cpp": "C++", ".c": "C", ".cs": "C#", ".php": "PHP",
    ".sh": "Shell", ".yml": "YAML", ".yaml": "YAML", ".json": "JSON",
    ".md": "Markdown", ".txt": "Text", ".html": "HTML", ".css": "CSS",
}

def read_local_directory(path: str) -> dict:
    """
    Validate a local path and summarise files by language.
    Returns: { "path": str, "file_count": int, "languages": dict, "error": str | None }
    """
    p = Path(path)

    if not p.exists():
        return {"path": path, "file_count": 0, "languages": {}, "error": f"Path does not exist: {path}"}
    if not p.is_dir():
        return {"path": path, "file_count": 0, "languages": {}, "error": f"Path is not a directory: {path}"}

    languages = {}
    file_count = 0

    for file in p.rglob("*"):
        if file.is_file():
            file_count += 1
            ext = file.suffix.lower()
            lang = EXTENSION_MAP.get(ext, "Other")
            languages[lang] = languages.get(lang, 0) + 1

    return {
        "path": str(p.resolve()),
        "file_count": file_count,
        "languages": languages,
        "error": None
    }


# ── 3. BANDIT WRAPPER ─────────────────────────────────────────────────────────
# Runs bandit with -f json, parses output, returns clean findings list

def run_bandit(path: str) -> dict:
    """
    Run bandit static analysis on a directory.
    Returns: { "findings": list[dict], "total": int, "error": str | None }
    """
    try:
        result = subprocess.run(
            ["python", "-m", "bandit", "-r", path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=120
        )

        # Bandit returns exit code 1 when issues are found — that's normal, not an error
        raw = result.stdout.strip()
        if not raw:
            return {"findings": [], "total": 0, "error": "Bandit produced no output"}

        data = json.loads(raw)
        results = data.get("results", [])

        findings = []
        for r in results:
            findings.append({
                "file": r.get("filename", ""),
                "line": r.get("line_number", 0),
                "issue": r.get("issue_text", ""),
                "severity": r.get("issue_severity", ""),      # LOW / MEDIUM / HIGH
                "confidence": r.get("issue_confidence", ""),  # LOW / MEDIUM / HIGH
                "test_id": r.get("test_id", ""),
            })

        return {"findings": findings, "total": len(findings), "error": None}

    except subprocess.TimeoutExpired:
        return {"findings": [], "total": 0, "error": "Bandit timed out"}
    except json.JSONDecodeError as e:
        return {"findings": [], "total": 0, "error": f"Failed to parse bandit output: {e}"}


# ── 4. PIP-AUDIT WRAPPER ──────────────────────────────────────────────────────
# Runs pip-audit with --format json, returns vulnerable packages

def run_pip_audit(path: str) -> dict:
    """
    Run pip-audit on a requirements.txt in the given directory.
    Returns: { "vulnerabilities": list[dict], "total": int, "error": str | None }
    """
    req_file = Path(path) / "requirements.txt"

    if not req_file.exists():
        return {
            "vulnerabilities": [],
            "total": 0,
            "error": f"No requirements.txt found in {path}"
        }

    try:
        result = subprocess.run(
            ["python", "-m", "pip_audit", "-r", str(req_file), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120
        )

        raw = result.stdout.strip()
        if not raw:
            return {"vulnerabilities": [], "total": 0, "error": "pip-audit produced no output"}

        data = json.loads(raw)
        deps = data.get("dependencies", [])

        vulnerabilities = []
        for dep in deps:
            for vuln in dep.get("vulns", []):
                vulnerabilities.append({
                    "package": dep.get("name", ""),
                    "current_version": dep.get("version", ""),
                    "vuln_id": vuln.get("id", ""),
                    "description": vuln.get("description", ""),
                    "fix_versions": vuln.get("fix_versions", []),
                })

        return {"vulnerabilities": vulnerabilities, "total": len(vulnerabilities), "error": None}

    except subprocess.TimeoutExpired:
        return {"vulnerabilities": [], "total": 0, "error": "pip-audit timed out"}
    except json.JSONDecodeError as e:
        return {"vulnerabilities": [], "total": 0, "error": f"Failed to parse pip-audit output: {e}"}


# ── SANITY CHECKS ─────────────────────────────────────────────────────────────
# Run this file directly to test each tool

if __name__ == "__main__":
    import pprint
    pp = pprint.PrettyPrinter(indent=2)

    print("=" * 60)
    print("TEST 1: Local directory reader (current folder)")
    print("=" * 60)
    result = read_local_directory(".")
    pp.pprint(result)

    print("\n" + "=" * 60)
    print("TEST 2: Bandit (current folder)")
    print("=" * 60)
    result = run_bandit(".")
    pp.pprint(result)

    print("\n" + "=" * 60)
    print("TEST 3: pip-audit (current folder)")
    print("=" * 60)
    result = run_pip_audit(".")
    pp.pprint(result)

    print("\n" + "=" * 60)
    print("TEST 4: GitHub fetcher (intentionally vulnerable repo)")
    print("=" * 60)
    result = fetch_github_repo("https://github.com/PyCQA/bandit")
    pp.pprint(result)
    # Clean up cloned repo after test
    if result["path"]:
        import shutil
        shutil.rmtree(result["path"], ignore_errors=True)
        print("(Cleaned up temp clone)")