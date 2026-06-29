# agent.py
# Vulnerability Finder Agent — Final version (Day 5)
# Usage: python agent.py --target <github_url_or_local_path> [--output ./reports]

import os
import shutil
import argparse
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, START, END
from tools import fetch_github_repo, read_local_directory, run_bandit, run_pip_audit
from enricher import enrich_with_cve, generate_report_with_llm, convert_to_html, save_report


# ── 1. STATE ──────────────────────────────────────────────────────────────────

class VulnScanState(TypedDict):
    target: str
    output_dir: str
    input_type: Optional[str]
    repo_path: Optional[str]
    fetch_error: Optional[str]
    code_findings: Optional[list]
    dep_findings: Optional[list]
    scan_error: Optional[str]
    cve_data: Optional[list]
    final_report: Optional[str]


# ── 2. NODES ──────────────────────────────────────────────────────────────────

def router_node(state: VulnScanState) -> dict:
    target = state["target"].strip()
    _status("router", f"Target: {target}")
    if target.startswith("https://github.com/"):
        _status("router", "→ GitHub URL detected")
        return {"input_type": "github"}
    _status("router", "→ Local path detected")
    return {"input_type": "local"}


def github_fetcher_node(state: VulnScanState) -> dict:
    _status("github_fetcher", f"Cloning {state['target']}...")
    result = fetch_github_repo(state["target"])
    if result["error"]:
        _status("github_fetcher", f"✗ {result['error']}", error=True)
        return {"repo_path": None, "fetch_error": result["error"]}
    _status("github_fetcher", f"✓ Cloned successfully")
    return {"repo_path": result["path"], "fetch_error": None}


def local_reader_node(state: VulnScanState) -> dict:
    _status("local_reader", f"Reading {state['target']}...")
    result = read_local_directory(state["target"])
    if result["error"]:
        _status("local_reader", f"✗ {result['error']}", error=True)
        return {"repo_path": None, "fetch_error": result["error"]}
    _status("local_reader", f"✓ Found {result['file_count']} files — {result['languages']}")
    return {"repo_path": result["path"], "fetch_error": None}


def code_scanner_node(state: VulnScanState) -> dict:
    if state.get("fetch_error"):
        _status("code_scanner", "Skipping — fetch failed", error=True)
        return {"code_findings": [], "scan_error": state["fetch_error"]}
    _status("code_scanner", "Running bandit static analysis...")
    result = run_bandit(state["repo_path"])
    if result["error"]:
        _status("code_scanner", f"✗ {result['error']}", error=True)
        return {"code_findings": [], "scan_error": result["error"]}
    _status("code_scanner", f"✓ {result['total']} code issues found")
    return {"code_findings": result["findings"], "scan_error": None}


def dep_scanner_node(state: VulnScanState) -> dict:
    if state.get("fetch_error"):
        return {"dep_findings": []}
    _status("dep_scanner", "Running pip-audit dependency check...")
    result = run_pip_audit(state["repo_path"])
    if result["error"]:
        _status("dep_scanner", f"ℹ {result['error']}")
        return {"dep_findings": []}
    _status("dep_scanner", f"✓ {result['total']} vulnerable dependencies found")
    return {"dep_findings": result["vulnerabilities"]}


def cve_enricher_node(state: VulnScanState) -> dict:
    dep_findings = state.get("dep_findings", [])
    if not dep_findings:
        _status("cve_enricher", "No dependency findings — skipping OSV lookup")
        return {"cve_data": []}
    _status("cve_enricher", f"Querying OSV.dev for {len(dep_findings)} packages...")
    enriched = enrich_with_cve(dep_findings)
    _status("cve_enricher", "✓ CVE enrichment complete")
    return {"cve_data": enriched}


def report_generator_node(state: VulnScanState) -> dict:
    groq_key = os.environ.get("GROQ_API_KEY")
    if not groq_key:
        _status("report_generator", "✗ GROQ_API_KEY not set in environment", error=True)
        return {"final_report": None}

    _status("report_generator", "Generating report with Groq LLM...")

    code_findings = state.get("code_findings", [])
    enriched_deps = state.get("cve_data", [])
    dep_findings = state.get("dep_findings", [])
    target = state.get("target", "unknown")
    output_dir = state.get("output_dir", "./reports")

    # Handle edge case: no findings at all
    if not code_findings and not dep_findings:
        markdown_report = f"# Security Report\n\n**Target:** {target}\n\n## Summary\n\nNo issues were identified. The codebase appears clean based on bandit static analysis and pip-audit dependency checks."
    else:
        try:
            markdown_report = generate_report_with_llm(
                target=target,
                code_findings=code_findings,
                dep_findings=dep_findings,
                enriched_deps=enriched_deps,
                groq_api_key=groq_key
            )
        except Exception as e:
            _status("report_generator", f"✗ LLM error: {e}", error=True)
            markdown_report = f"# Security Report\n\n**Target:** {target}\n\n## Error\n\nLLM report generation failed: {e}\n\n## Raw Findings\n\n{len(code_findings)} code issues, {len(dep_findings)} dependency vulnerabilities found."

    html = convert_to_html(markdown_report, target)
    filepath = save_report(html, output_dir)
    _status("report_generator", f"✓ Report saved → {filepath}")

    # Clean up temp clone
    repo_path = state.get("repo_path", "")
    if repo_path and "vuln_scan_" in repo_path:
        shutil.rmtree(repo_path, ignore_errors=True)
        _status("report_generator", "Cleaned up temp clone")

    return {"final_report": filepath}


# ── 3. HELPERS ────────────────────────────────────────────────────────────────

def _status(node: str, message: str, error: bool = False):
    """Print a one-line status update per node."""
    prefix = "✗" if error else "›"
    print(f"  {prefix} [{node}] {message}")


# ── 4. ROUTING ────────────────────────────────────────────────────────────────

def route_to_fetcher(state: VulnScanState) -> str:
    return "github_fetcher" if state["input_type"] == "github" else "local_reader"


# ── 5. BUILD GRAPH ────────────────────────────────────────────────────────────

def build_graph():
    builder = StateGraph(VulnScanState)

    builder.add_node("router", router_node)
    builder.add_node("github_fetcher", github_fetcher_node)
    builder.add_node("local_reader", local_reader_node)
    builder.add_node("code_scanner", code_scanner_node)
    builder.add_node("dep_scanner", dep_scanner_node)
    builder.add_node("cve_enricher", cve_enricher_node)
    builder.add_node("report_generator", report_generator_node)

    builder.add_edge(START, "router")
    builder.add_conditional_edges(
        "router",
        route_to_fetcher,
        {"github_fetcher": "github_fetcher", "local_reader": "local_reader"}
    )
    builder.add_edge("github_fetcher", "code_scanner")
    builder.add_edge("local_reader", "code_scanner")
    builder.add_edge("code_scanner", "dep_scanner")
    builder.add_edge("dep_scanner", "cve_enricher")
    builder.add_edge("cve_enricher", "report_generator")
    builder.add_edge("report_generator", END)

    return builder.compile()


# ── 6. CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Finder Agent — scans Python repos for security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --target https://github.com/fportantier/vulpy
  python agent.py --target ./my-project
  python agent.py --target https://github.com/org/repo --output ./reports
        """
    )
    parser.add_argument(
        "--target", required=True,
        help="GitHub URL or local path to scan"
    )
    parser.add_argument(
        "--output", default="./reports",
        help="Directory to save the HTML report (default: ./reports)"
    )
    args = parser.parse_args()

    # Validate GROQ_API_KEY early
    if not os.environ.get("GROQ_API_KEY"):
        print("\n✗ Error: GROQ_API_KEY environment variable is not set.")
        print("  Set it with: $env:GROQ_API_KEY=\"your-key-here\"  (PowerShell)")
        print("  Get a free key at: https://console.groq.com/keys\n")
        return

    print()
    print("╔══════════════════════════════════════════╗")
    print("║      Vulnerability Finder Agent          ║")
    print("╚══════════════════════════════════════════╝")
    print(f"  Target : {args.target}")
    print(f"  Output : {args.output}")
    print()

    graph = build_graph()

    result = graph.invoke({
        "target": args.target,
        "output_dir": args.output,
        "input_type": None,
        "repo_path": None,
        "fetch_error": None,
        "code_findings": None,
        "dep_findings": None,
        "scan_error": None,
        "cve_data": None,
        "final_report": None,
    })

    if result.get("final_report"):
        print(f"\n  ✓ Scan complete!")
        print(f"  ✓ Open your report: {result['final_report']}\n")
    else:
        print("\n  ✗ Scan failed — check errors above\n")


if __name__ == "__main__":
    main()