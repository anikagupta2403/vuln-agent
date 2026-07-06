# fix_agent.py
# Fix Agent — proposes and applies targeted code fixes for HIGH severity findings
# Human approves or rejects each fix individually via interrupt()

import os
import json
from pathlib import Path
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage


# ── SUPPORTED FIX TYPES ───────────────────────────────────────────────────────

FIXABLE_IDS = {"B201", "B608", "B105", "B106", "B113", "B310"}

SYSTEM_PROMPT = """You are a security engineer fixing Python code vulnerabilities.

You will be given a vulnerable code snippet and the bandit issue description.

Return ONLY the fixed version of the code snippet — no explanation, no markdown backticks, no preamble.
Just the fixed code that directly replaces the original.

Rules:
- Make the minimal change needed to fix the security issue
- Preserve all existing logic, indentation, and surrounding code structure
- For B201 (Flask debug=True): change to debug=False
- For B608 (SQL injection): use parameterized queries with ? or %s placeholders
- For B105/B106 (hardcoded password): replace with os.environ.get('PASSWORD', '')
- For B113 (no request timeout): add timeout=10 to the requests call
- For B310 (URL open): add URL validation before opening
- If you cannot safely fix it, return the original code unchanged"""

ISSUE_DESCRIPTIONS = {
    "B201": "Flask app running with debug=True — exposes Werkzeug debugger, allows arbitrary code execution",
    "B608": "Possible SQL injection — string-formatted query can be manipulated by user input",
    "B105": "Hardcoded password string — credentials should never be in source code",
    "B106": "Hardcoded password in function argument — use environment variables instead",
    "B113": "HTTP request without timeout — can hang indefinitely, enabling DoS",
    "B310": "URL open without validation — could be used to access internal resources",
}


# ── HELPERS ───────────────────────────────────────────────────────────────────

def read_code_context(filepath: str, line: int, context: int = 5) -> str:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
        start = max(0, line - context - 1)
        end = min(len(all_lines), line + context)
        return "".join(all_lines[start:end])
    except Exception:
        return ""


def apply_fix_to_file(filepath: str, original_snippet: str, fixed_snippet: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if original_snippet.strip() not in content:
            return False
        new_content = content.replace(original_snippet, fixed_snippet, 1)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)
        return True
    except Exception:
        return False


def resolve_filepath(filepath: str, repo_path: str) -> str:
    if filepath.startswith(".\\") or filepath.startswith("./"):
        filepath = os.path.join(repo_path, filepath[2:])
    elif not os.path.isabs(filepath):
        filepath = os.path.join(repo_path, filepath)
    return filepath


def get_llm_fix(original_snippet: str, test_id: str, issue: str, filepath: str, line: int, llm: ChatGroq) -> str:
    """Ask LLM to produce the fixed code snippet."""
    response = llm.invoke([
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Fix this security issue:

Bandit ID: {test_id}
Issue: {issue}
File: {filepath}
Line: {line}

Vulnerable code:
{original_snippet}

Return only the fixed code snippet.""")
    ])
    return response.content.strip()


def show_diff(original: str, fixed: str):
    """Print a simple before/after diff."""
    orig_lines = original.strip().splitlines()
    fixed_lines = fixed.strip().splitlines()

    print("\n    ┌─ CURRENT CODE ──────────────────────────")
    for line in orig_lines:
        print(f"    │  {line}")
    print("    ├─ PROPOSED FIX ──────────────────────────")
    for line in fixed_lines:
        print(f"    │  {line}")
    print("    └─────────────────────────────────────────\n")


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

def prepare_fixes(code_findings: list, repo_path: str, groq_api_key: str) -> list:
    """
    For each HIGH severity fixable finding, generate the proposed fix.
    Returns a list of fix proposals (without applying them yet).
    Each proposal contains: finding info + original snippet + proposed fix.
    """
    high_findings = [
        f for f in code_findings
        if f.get("severity", "").upper() == "HIGH"
        and f.get("test_id", "") in FIXABLE_IDS
    ]

    if not high_findings:
        return []

    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=groq_api_key,
        temperature=0
    )

    proposals = []
    for finding in high_findings:
        test_id = finding.get("test_id", "")
        filepath = resolve_filepath(finding.get("file", ""), repo_path)
        line = finding.get("line", 0)
        issue = finding.get("issue", "")

        if not os.path.exists(filepath):
            continue

        original_snippet = read_code_context(filepath, line)
        if not original_snippet.strip():
            continue

        try:
            fixed_snippet = get_llm_fix(original_snippet, test_id, issue, filepath, line, llm)
            # Skip if LLM returned something clearly wrong
            if not fixed_snippet or len(fixed_snippet) > len(original_snippet) * 3:
                continue

            proposals.append({
                "test_id": test_id,
                "filepath": filepath,
                "filename": Path(filepath).name,
                "line": line,
                "issue": issue,
                "description": ISSUE_DESCRIPTIONS.get(test_id, issue),
                "original_snippet": original_snippet,
                "fixed_snippet": fixed_snippet,
                "status": "pending",
            })
        except Exception as e:
            print(f"  ✗ [fix_agent] Could not generate fix for {test_id}: {e}")

    return proposals


def apply_approved_fix(proposal: dict) -> dict:
    """Apply a single approved fix to the file."""
    success = apply_fix_to_file(
        proposal["filepath"],
        proposal["original_snippet"],
        proposal["fixed_snippet"]
    )
    proposal["status"] = "fixed" if success else "failed"
    return proposal