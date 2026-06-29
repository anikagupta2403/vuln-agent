# enricher.py
# Day 4: CVE Enrichment + Report Generation
# - Hits OSV.dev API to get severity + patch data for dependency findings
# - Passes all findings to Groq LLM to generate a readable report
# - Converts markdown report to HTML with timestamp

import os
import json
import requests
from datetime import datetime


# ── 1. CVE ENRICHER ───────────────────────────────────────────────────────────
# Hits OSV.dev API for each vulnerable dependency
# No API key needed — completely free

OSV_API = "https://api.osv.dev/v1/query"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def enrich_with_cve(dep_findings: list) -> list:
    """
    For each dependency finding, query OSV.dev for CVSS severity and patch info.
    Caps at 20 findings to avoid timeouts.
    Returns enriched list with severity classification added.
    """
    enriched = []

    for dep in dep_findings[:20]:  # cap at 20 per project brief
        package = dep.get("package", "")
        version = dep.get("current_version", "")
        vuln_id = dep.get("vuln_id", "")

        print(f"  [enricher] Querying OSV for {package} {version}...")

        try:
            payload = {
                "package": {"name": package, "ecosystem": "PyPI"},
                "version": version
            }
            response = requests.post(OSV_API, json=payload, timeout=10)
            data = response.json()
            vulns = data.get("vulns", [])

            # Extract severity from first matching vuln
            severity = "UNKNOWN"
            cvss_score = None

            for v in vulns:
                for severity_entry in v.get("severity", []):
                    score_str = severity_entry.get("score", "")
                    # CVSS scores look like "CVSS:3.1/AV:N/AC:L/..." or just a number
                    if "CVSS" in score_str or severity_entry.get("type") == "CVSS_V3":
                        # Try to extract base score
                        try:
                            base = float(score_str.split("/")[-1]) if "/" in score_str else float(score_str)
                            cvss_score = base
                        except ValueError:
                            pass

                # Fall back to database_specific severity
                if severity == "UNKNOWN":
                    db = v.get("database_specific", {})
                    sev = db.get("severity", "").upper()
                    if sev in SEVERITY_ORDER:
                        severity = sev

            # Classify by CVSS score if we got one
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            enriched.append({
                **dep,
                "severity": severity,
                "cvss_score": cvss_score,
                "osv_vuln_count": len(vulns),
            })

        except requests.Timeout:
            print(f"  [enricher] Timeout for {package} — skipping enrichment")
            enriched.append({**dep, "severity": "UNKNOWN", "cvss_score": None, "osv_vuln_count": 0})
        except Exception as e:
            print(f"  [enricher] Error for {package}: {e}")
            enriched.append({**dep, "severity": "UNKNOWN", "cvss_score": None, "osv_vuln_count": 0})

    return enriched


def classify_code_finding_severity(finding: dict) -> str:
    """Map bandit severity field to our standard severity levels."""
    sev = finding.get("severity", "").upper()
    mapping = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return mapping.get(sev, "UNKNOWN")


# ── 2. LLM REPORT GENERATOR ───────────────────────────────────────────────────
# Passes all enriched findings to Groq (Llama 3) and gets a markdown report back

def generate_report_with_llm(
    target: str,
    code_findings: list,
    dep_findings: list,
    enriched_deps: list,
    groq_api_key: str
) -> str:
    """
    Sends all findings to Groq LLM and returns a markdown report.
    """
    from langchain_groq import ChatGroq
    from langchain_core.messages import HumanMessage, SystemMessage

    # Classify code findings by severity
    classified_code = []
    for f in code_findings:
        classified_code.append({
            **f,
            "classified_severity": classify_code_finding_severity(f)
        })

    # Sort by severity
    classified_code.sort(key=lambda x: SEVERITY_ORDER.get(x["classified_severity"], 4))
    enriched_deps.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 4))

    # Build the prompt
    findings_summary = f"""
TARGET: {target}

CODE FINDINGS (bandit) — {len(classified_code)} total:
{json.dumps(classified_code[:30], indent=2)}

DEPENDENCY VULNERABILITIES (pip-audit + OSV) — {len(enriched_deps)} total:
{json.dumps(enriched_deps, indent=2)}
"""

    system_prompt = """You are a security analyst writing a vulnerability report for a development team.
Given raw scan findings, produce a clear, well-structured Markdown report with:

1. An executive summary (2-3 sentences) stating overall risk level
2. A CRITICAL/HIGH findings section — explain why each is dangerous and what to do
3. A MEDIUM findings section — group similar issues together
4. A LOW findings section — brief mention only
5. Dependency vulnerabilities section — list affected packages, CVE IDs, and fix versions
6. Recommended next steps (top 3 actions the team should take)

Be specific and actionable. Reference file names and line numbers where relevant.
If there are no findings in a category, say so clearly rather than omitting the section.
Write in professional but plain English — no jargon without explanation."""

    print("\n[report_generator] Sending findings to Groq LLM...")

    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=groq_api_key,
        temperature=0
    )

    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"Please analyse these findings and write the security report:\n{findings_summary}")
    ])

    return response.content


# ── 3. MARKDOWN → HTML CONVERTER ──────────────────────────────────────────────

REPORT_CSS = """
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    max-width: 900px;
    margin: 40px auto;
    padding: 0 24px;
    background: #0f1117;
    color: #e2e8f0;
    line-height: 1.7;
}
h1 { color: #f97316; border-bottom: 2px solid #f97316; padding-bottom: 8px; }
h2 { color: #fb923c; margin-top: 36px; }
h3 { color: #94a3b8; }
code {
    background: #1e2330;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
    color: #7dd3fc;
}
pre {
    background: #1e2330;
    padding: 16px;
    border-radius: 8px;
    overflow-x: auto;
    border-left: 4px solid #f97316;
}
pre code { background: none; padding: 0; }
ul { padding-left: 24px; }
li { margin: 6px 0; }
strong { color: #f8fafc; }
p { color: #cbd5e1; }
hr { border: none; border-top: 1px solid #2d3748; margin: 32px 0; }
.header-meta {
    background: #1e2330;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 32px;
    font-size: 0.9em;
    color: #94a3b8;
}
"""

def convert_to_html(markdown_content: str, target: str) -> str:
    """Convert markdown report to styled HTML."""
    try:
        import markdown
        body = markdown.markdown(markdown_content, extensions=["fenced_code", "tables"])
    except ImportError:
        # Fallback: wrap in pre if markdown package not available
        body = f"<pre>{markdown_content}</pre>"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report — {target}</title>
    <style>{REPORT_CSS}</style>
</head>
<body>
    <h1>🔍 Vulnerability Report</h1>
    <div class="header-meta">
        <strong>Target:</strong> {target}<br>
        <strong>Generated:</strong> {timestamp}<br>
        <strong>Scanner:</strong> bandit + pip-audit + OSV.dev + Groq LLaMA 3
    </div>
    {body}
</body>
</html>"""


def save_report(html_content: str, output_dir: str = "./reports") -> str:
    """Save the HTML report with a timestamp in the filename."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/findings_{timestamp}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filename