# pr_opener.py
# PR Opener — creates a branch, commits fixed files, opens a GitHub PR
# Uses GitHub REST API — no extra packages needed beyond requests

import os
import re
import base64
import requests
from datetime import datetime
from pathlib import Path


GITHUB_API = "https://api.github.com"


# ── HELPERS ───────────────────────────────────────────────────────────────────

def get_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract owner and repo name from GitHub URL."""
    match = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", url)
    if not match:
        raise ValueError(f"Cannot parse GitHub URL: {url}")
    return match.group(1), match.group(2)


def get_default_branch(owner: str, repo: str, headers: dict) -> str:
    response = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers)
    response.raise_for_status()
    return response.json()["default_branch"]


def get_branch_sha(owner: str, repo: str, branch: str, headers: dict) -> str:
    response = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{branch}",
        headers=headers
    )
    response.raise_for_status()
    return response.json()["object"]["sha"]


def create_branch(owner: str, repo: str, branch_name: str, sha: str, headers: dict) -> bool:
    response = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": sha}
    )
    return response.status_code == 201


def get_file_sha(owner: str, repo: str, filepath: str, branch: str, headers: dict) -> str | None:
    response = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/{filepath}",
        headers=headers,
        params={"ref": branch}
    )
    if response.status_code == 200:
        return response.json()["sha"]
    return None


def commit_file(owner: str, repo: str, filepath: str, content: str, branch: str, message: str, headers: dict) -> bool:
    encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    existing_sha = get_file_sha(owner, repo, filepath, branch, headers)
    payload = {
        "message": message,
        "content": encoded,
        "branch": branch,
    }
    if existing_sha:
        payload["sha"] = existing_sha
    response = requests.put(
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/{filepath}",
        headers=headers,
        json=payload
    )
    return response.status_code in (200, 201)


def open_pull_request(owner, repo, branch_name, default_branch, fix_results, report_path, headers):
    fixed = [f for f in fix_results if f.get("status") == "fixed"]
    body = "## 🔍 Automated Security Fixes\n\n"
    body += "This PR was opened automatically by the **Vulnerability Finder Agent**.\n\n"
    body += "### What was fixed\n\n"
    for f in fixed:
        body += f"- **{f['test_id']}** in `{f['filename']}` (line {f['line']})\n"
        body += f"  > {f['description']}\n\n"
    body += "### How fixes were applied\n\n"
    body += "1. Proposed by the fix agent (Groq LLaMA 3)\n"
    body += "2. **Reviewed and approved by a human** before being applied\n"
    body += "3. Verified by a critic agent for report quality\n\n"
    body += f"> ⚠️ Please review these changes carefully before merging.\n"

    response = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
        headers=headers,
        json={
            "title": f"[Security] Auto-fix {len(fixed)} HIGH severity vulnerabilities",
            "body": body,
            "head": branch_name,
            "base": default_branch,
        }
    )
    if response.status_code == 201:
        return {"success": True, "url": response.json()["html_url"]}
    else:
        return {"success": False, "error": response.json().get("message", "Unknown error")}


def open_pr_with_fixes(target_url, repo_path, fix_results, report_path, github_token):
    fixed = [f for f in fix_results if f.get("status") == "fixed"]
    if not fixed:
        return {"success": False, "error": "No fixes to commit"}

    try:
        owner, repo = parse_github_url(target_url)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    headers = get_headers(github_token)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    branch_name = f"security-fixes/vuln-agent-{timestamp}"

    print(f"  › [pr_opener] Target repo: {owner}/{repo}")
    print(f"  › [pr_opener] Creating branch: {branch_name}")

    try:
        default_branch = get_default_branch(owner, repo, headers)
        base_sha = get_branch_sha(owner, repo, default_branch, headers)

        if not create_branch(owner, repo, branch_name, base_sha, headers):
            return {"success": False, "error": "Failed to create branch"}

        print(f"  › [pr_opener] ✓ Branch created")

        committed_files = set()
        for fix in fixed:
            filepath = fix["filepath"]
            try:
                rel_path = str(Path(filepath).relative_to(repo_path)).replace("\\", "/")
            except ValueError:
                rel_path = filepath.replace(repo_path, "").lstrip("/\\").replace("\\", "/")

            if rel_path in committed_files:
                continue

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"  ✗ [pr_opener] Could not read {filepath}: {e}")
                continue

            commit_msg = f"fix({fix['test_id']}): {fix['description'][:60]}"
            success = commit_file(owner, repo, rel_path, content, branch_name, commit_msg, headers)

            if success:
                committed_files.add(rel_path)
                print(f"  › [pr_opener] ✓ Committed {rel_path}")
            else:
                print(f"  ✗ [pr_opener] Failed to commit {rel_path}")

        if not committed_files:
            return {"success": False, "error": "No files could be committed"}

        print(f"  › [pr_opener] Opening pull request...")
        result = open_pull_request(owner, repo, branch_name, default_branch, fix_results, report_path, headers)

        if result["success"]:
            print(f"  › [pr_opener] ✓ PR opened → {result['url']}")
        else:
            print(f"  ✗ [pr_opener] PR failed: {result['error']}")

        return result

    except requests.HTTPError as e:
        return {"success": False, "error": f"GitHub API error: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}