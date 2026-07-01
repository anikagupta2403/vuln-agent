# agent.py
# Vulnerability Finder Agent — with Human in the Loop + Fix Agent
# Usage: python agent.py --target <github_url_or_local_path> [--output ./reports]

import os
import shutil
import argparse
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import interrupt, Command
from tools import fetch_github_repo, read_local_directory, run_bandit, run_pip_audit
from enricher import enrich_with_cve, generate_report_with_llm, convert_to_html, save_report
from fix_agent import run_fix_agent


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
    human_approved: Optional[bool]
    fix_results: Optional[dict]       # NEW: results from fix agent
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
    _status("github_fetcher", "✓ Cloned successfully")
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


def human_review_node(state: VulnScanState) -> dict:
    """
    Pauses graph, shows findings summary, asks user to approve.
    Also asks if they want the fix agent to run.
    """
    code_findings = state.get("code_findings", [])
    dep_findings = state.get("dep_findings", [])
    cve_data = state.get("cve_data", [])

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in code_findings:
        sev = f.get("severity", "LOW").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    critical_deps = [d for d in cve_data if d.get("severity") in ("CRITICAL", "HIGH")]

    print()
    print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("    FINDINGS SUMMARY")
    print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"    Code issues total   : {len(code_findings)}")
    print(f"      High              : {severity_counts['HIGH']}")
    print(f"      Medium            : {severity_counts['MEDIUM']}")
    print(f"      Low               : {severity_counts['LOW']}")
    print(f"    Dep vulnerabilities : {len(dep_findings)}")
    if cve_data:
        print(f"      Critical/High     : {len(critical_deps)}")
    print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()

    user_input = interrupt({
        "question": "Proceed with report generation?",
        "findings_count": len(code_findings),
        "dep_count": len(dep_findings),
    })

    approved = str(user_input).strip().lower() in ("yes", "y")
    if approved:
        _status("human_review", "✓ Approved — proceeding")
    else:
        _status("human_review", "✗ Rejected — stopping")

    return {"human_approved": approved}


def fix_agent_node(state: VulnScanState) -> dict:
    """
    Runs the fix agent on HIGH severity findings.
    Only runs if human approved and repo is available.
    """
    if not state.get("human_approved"):
        return {"fix_results": None}

    repo_path = state.get("repo_path")
    if not repo_path:
        _status("fix_agent", "No repo path — skipping fixes", error=True)
        return {"fix_results": None}

    groq_key = os.environ.get("GROQ_API_KEY")
    if not groq_key:
        _status("fix_agent", "✗ GROQ_API_KEY not set", error=True)
        return {"fix_results": None}

    code_findings = state.get("code_findings", [])
    high_count = sum(1 for f in code_findings if f.get("severity", "").upper() == "HIGH")

    if high_count == 0:
        _status("fix_agent", "No HIGH severity issues to fix — skipping")
        return {"fix_results": {"summary": "No HIGH severity issues to fix", "total_fixed": 0}}

    _status("fix_agent", f"Attempting to fix {high_count} HIGH severity issues...")
    results = run_fix_agent(code_findings, repo_path, groq_key)
    _status("fix_agent", f"✓ {results['summary']}")

    return {"fix_results": results}


def report_generator_node(state: VulnScanState) -> dict:
    if not state.get("human_approved"):
        _status("report_generator", "Skipped — not approved")
        return {"final_report": None}

    groq_key = os.environ.get("GROQ_API_KEY")
    if not groq_key:
        _status("report_generator", "✗ GROQ_API_KEY not set", error=True)
        return {"final_report": None}

    _status("report_generator", "Generating report with Groq LLM...")

    code_findings = state.get("code_findings", [])
    dep_findings = state.get("dep_findings", [])
    enriched_deps = state.get("cve_data", [])
    fix_results = state.get("fix_results")
    target = state.get("target", "unknown")
    output_dir = state.get("output_dir", "./reports")

    if not code_findings and not dep_findings:
        markdown_report = f"# Security Report\n\n**Target:** {target}\n\n## Summary\n\nNo issues identified."
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
            markdown_report = f"# Security Report\n\n**Target:** {target}\n\n## Error\n\nLLM failed: {e}"

    # Append fix summary to report if fixes were applied
    if fix_results and fix_results.get("total_fixed", 0) > 0:
        fixes = fix_results.get("fixes_applied", [])
        fixed_list = [f for f in fixes if f["status"] == "fixed"]
        fix_section = "\n\n## Automated Fixes Applied\n\n"
        fix_section += f"The fix agent automatically patched **{len(fixed_list)}** HIGH severity issues:\n\n"
        for f in fixed_list:
            from pathlib import Path
            fix_section += f"- `{Path(f['file']).name}` line {f['line']} — {f['test_id']}: {f['issue'][:80]}\n"
        fix_section += "\n> These fixes have been applied to the local repository copy.\n"
        markdown_report += fix_section

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
    prefix = "✗" if error else "›"
    print(f"  {prefix} [{node}] {message}")


# ── 4. ROUTING ────────────────────────────────────────────────────────────────

def route_to_fetcher(state: VulnScanState) -> str:
    return "github_fetcher" if state["input_type"] == "github" else "local_reader"


# ── 5. BUILD GRAPH ────────────────────────────────────────────────────────────

def build_graph(checkpointer):
    builder = StateGraph(VulnScanState)

    builder.add_node("router", router_node)
    builder.add_node("github_fetcher", github_fetcher_node)
    builder.add_node("local_reader", local_reader_node)
    builder.add_node("code_scanner", code_scanner_node)
    builder.add_node("dep_scanner", dep_scanner_node)
    builder.add_node("cve_enricher", cve_enricher_node)
    builder.add_node("human_review", human_review_node)
    builder.add_node("fix_agent", fix_agent_node)
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
    builder.add_edge("cve_enricher", "human_review")
    builder.add_edge("human_review", "fix_agent")       # fix agent runs after approval
    builder.add_edge("fix_agent", "report_generator")
    builder.add_edge("report_generator", END)

    return builder.compile(checkpointer=checkpointer)


# ── 6. CLI + RUN ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Finder Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --target https://github.com/fportantier/vulpy
  python agent.py --target ./my-project --output ./reports
        """
    )
    parser.add_argument("--target", required=True, help="GitHub URL or local path to scan")
    parser.add_argument("--output", default="./reports", help="Directory to save HTML report")
    args = parser.parse_args()

    if not os.environ.get("GROQ_API_KEY"):
        print("\n✗ Error: GROQ_API_KEY not set.")
        print("  Set it with: $env:GROQ_API_KEY=\"your-key-here\"  (PowerShell)\n")
        return

    print()
    print("╔══════════════════════════════════════════╗")
    print("║      Vulnerability Finder Agent          ║")
    print("╚══════════════════════════════════════════╝")
    print(f"  Target : {args.target}")
    print(f"  Output : {args.output}")
    print()

    with SqliteSaver.from_conn_string(":memory:") as checkpointer:
        graph = build_graph(checkpointer)
        config = {"configurable": {"thread_id": "scan-1"}}

        initial_state = {
            "target": args.target,
            "output_dir": args.output,
            "input_type": None,
            "repo_path": None,
            "fetch_error": None,
            "code_findings": None,
            "dep_findings": None,
            "scan_error": None,
            "cve_data": None,
            "human_approved": None,
            "fix_results": None,
            "final_report": None,
        }

        # Stream until interrupt
        for event in graph.stream(initial_state, config=config, stream_mode="updates"):
            if "__interrupt__" in event:
                user_input = input("  Proceed with report generation? (yes/no): ").strip()
                print()
                result = graph.invoke(
                    Command(resume=user_input),
                    config=config
                )

                # Print fix summary if available
                fix_results = result.get("fix_results")
                if fix_results and fix_results.get("total_fixed", 0) > 0:
                    print(f"\n  ✓ Auto-fixed {fix_results['total_fixed']} HIGH severity issues")

                if result.get("final_report"):
                    print(f"\n  ✓ Scan complete!")
                    print(f"  ✓ Open your report: {result['final_report']}\n")
                else:
                    print("\n  ✗ Scan cancelled\n")
                return

        print("\n  ✗ Scan failed\n")


if __name__ == "__main__":
    main()