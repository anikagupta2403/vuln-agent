# fix_agent.py
# Fix Agent — reads HIGH severity bandit findings and applies targeted code fixes
# Handles: B201 (Flask debug), B608 (SQL injection), B105/B106 (hardcoded passwords),
#          B113 (no timeout), B310 (URL open)

import os
import json
from pathlib import Path
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage


# ── SUPPORTED FIX TYPES ───────────────────────────────────────────────────────

FIXABLE_IDS = {"B201", "B608", "B105", "B106", "B113", "B310"}

SYSTEM_PROMPT = """You are a security engineer fixing Python code vulnerabilities.

You will be given:
1. A vulnerable code snippet with the issue described
2. The bandit test ID and issue description

Your job is to return ONLY the fixed version of the code snippet — no explanation, 
no markdown backticks, no preamble. Just the fixed code that directly replaces the original.

Rules:
- Make the minimal change needed to fix the security issue
- Preserve all existing logic, indentation, and surrounding code structure
- For B201 (Flask debug=True): change to debug=False or use env variable
- For B608 (SQL injection): use parameterized queries with ? or %s placeholders
- For B105/B106 (hardcoded password): replace with os.environ.get('PASSWORD', '')
- For B113 (no request timeout): add timeout=10 to the requests call
- For B310 (URL open): add URL validation before opening
- If you cannot safely fix it, return the original code unchanged"""


# ── CORE FIX FUNCTION ─────────────────────────────────────────────────────────

def read_code_context(filepath: str, line: int, context: int = 5) -> tuple[str, list]:
    """
    Read lines around the vulnerable line for context.
    Returns (code_snippet, all_lines)
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()

        start = max(0, line - context - 1)
        end = min(len(all_lines), line + context)
        snippet = "".join(all_lines[start:end])
        return snippet, all_lines
    except Exception as e:
        return "", []


def apply_fix_to_file(filepath: str, original_snippet: str, fixed_snippet: str, line: int, context: int = 5) -> bool:
    """Replace the original snippet with the fixed version in the file."""
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


def fix_finding(finding: dict, repo_path: str, llm: ChatGroq) -> dict:
    """
    Attempt to fix a single bandit finding.
    Returns a fix result dict.
    """
    test_id = finding.get("test_id", "")
    filepath = finding.get("file", "")
    line = finding.get("line", 0)
    issue = finding.get("issue", "")
    severity = finding.get("severity", "")

    # Only fix HIGH severity and supported issue types
    if severity.upper() != "HIGH" or test_id not in FIXABLE_IDS:
        return {
            "file": filepath,
            "line": line,
            "test_id": test_id,
            "issue": issue,
            "status": "skipped",
            "reason": f"Not in fixable scope (severity={severity}, id={test_id})"
        }

    # Make filepath absolute using repo_path
    if filepath.startswith(".\\") or filepath.startswith("./"):
        filepath = os.path.join(repo_path, filepath[2:])
    elif not os.path.isabs(filepath):
        filepath = os.path.join(repo_path, filepath)

    if not os.path.exists(filepath):
        return {
            "file": filepath,
            "line": line,
            "test_id": test_id,
            "issue": issue,
            "status": "failed",
            "reason": "File not found"
        }

    # Read vulnerable code context
    original_snippet, _ = read_code_context(filepath, line)
    if not original_snippet.strip():
        return {
            "file": filepath,
            "line": line,
            "test_id": test_id,
            "issue": issue,
            "status": "failed",
            "reason": "Could not read code context"
        }

    # Ask LLM to fix it
    try:
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

        fixed_snippet = response.content.strip()

        # Don't apply if LLM returned something clearly wrong
        if not fixed_snippet or len(fixed_snippet) > len(original_snippet) * 3:
            return {
                "file": filepath,
                "line": line,
                "test_id": test_id,
                "issue": issue,
                "status": "failed",
                "reason": "LLM returned unexpected output"
            }

        # Apply the fix
        success = apply_fix_to_file(filepath, original_snippet, fixed_snippet, line)

        if success:
            return {
                "file": filepath,
                "line": line,
                "test_id": test_id,
                "issue": issue,
                "status": "fixed",
                "original": original_snippet,
                "fixed": fixed_snippet,
            }
        else:
            return {
                "file": filepath,
                "line": line,
                "test_id": test_id,
                "issue": issue,
                "status": "failed",
                "reason": "Could not apply fix to file"
            }

    except Exception as e:
        return {
            "file": filepath,
            "line": line,
            "test_id": test_id,
            "issue": issue,
            "status": "failed",
            "reason": str(e)
        }


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

def run_fix_agent(code_findings: list, repo_path: str, groq_api_key: str) -> dict:
    """
    Run the fix agent on all HIGH severity findings.
    Returns summary of fixes applied.
    """
    # Filter to HIGH severity fixable findings
    high_findings = [
        f for f in code_findings
        if f.get("severity", "").upper() == "HIGH"
        and f.get("test_id", "") in FIXABLE_IDS
    ]

    if not high_findings:
        return {
            "fixes_applied": [],
            "total_attempted": 0,
            "total_fixed": 0,
            "total_failed": 0,
            "total_skipped": 0,
            "summary": "No HIGH severity fixable issues found"
        }

    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=groq_api_key,
        temperature=0
    )

    print(f"  › [fix_agent] Found {len(high_findings)} HIGH severity fixable issues")

    fixes = []
    for i, finding in enumerate(high_findings):
        print(f"  › [fix_agent] Fixing {i+1}/{len(high_findings)}: {finding.get('test_id')} in {Path(finding.get('file','')).name}:{finding.get('line')}")
        result = fix_finding(finding, repo_path, llm)
        fixes.append(result)
        status_icon = "✓" if result["status"] == "fixed" else "✗"
        print(f"  {status_icon} [fix_agent] {result['status'].upper()} — {result.get('reason', '')}")

    fixed = [f for f in fixes if f["status"] == "fixed"]
    failed = [f for f in fixes if f["status"] == "failed"]
    skipped = [f for f in fixes if f["status"] == "skipped"]

    return {
        "fixes_applied": fixes,
        "total_attempted": len(high_findings),
        "total_fixed": len(fixed),
        "total_failed": len(failed),
        "total_skipped": len(skipped),
        "summary": f"Fixed {len(fixed)}/{len(high_findings)} HIGH severity issues"
    }
