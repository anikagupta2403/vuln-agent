# agent.py
# Vulnerability Finder Agent — Full pipeline with PR opener
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
from fix_agent import prepare_fixes, apply_approved_fix, show_diff
from critic_agent import run_critic, regenerate_with_feedback, format_critic_section
from pr_opener import open_pr_with_fixes


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
    fix_proposals: Optional[list]
    fix_results: Optional[list]
    markdown_report: Optional[str]
    critic_feedback: Optional[dict]
    critic_iteration: Optional[int]
    final_report: Optional[str]
    pr_url: Optional[str]


def _status(node: str, message: str, error: bool = False):
    prefix = "✗" if error else "›"
    print(f"  {prefix} [{node}] {message}")


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
    code_findings = state.get("code_findings", [])
    dep_findings = state.get("dep_findings", [])
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in code_findings:
        sev = f.get("severity", "LOW").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    print()
    print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("    FINDINGS SUMMARY")
    print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"    Code issues total   : {len(code_findings)}")
    print(f"      High              : {severity_counts['HIGH']}")
    print(f"      Medium            : {severity_counts['MEDIUM']}")
    print(f"      Low               : {severity_counts['LOW']}")
    print(f"    Dep vulnerabilities : {len(dep_findings)}")
    print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()

    user_input = interrupt("Proceed with fix proposals and report generation?")
    approved = str(user_input).strip().lower() in ("yes", "y")
    if approved:
        _status("human_review", "✓ Approved — preparing fixes")
    else:
        _status("human_review", "✗ Rejected — stopping")
    return {"human_approved": approved}


def fix_proposal_node(state: VulnScanState) -> dict:
    if not state.get("human_approved"):
        return {"fix_proposals": [], "fix_results": []}
    repo_path = state.get("repo_path")
    if not repo_path:
        _status("fix_proposal", "No repo path — skipping fixes")
        return {"fix_proposals": [], "fix_results": []}
    groq_key = os.environ.get("GROQ_API_KEY")
    code_findings = state.get("code_findings", [])
    high_count = sum(1 for f in code_findings if f.get("severity", "").upper() == "HIGH")
    if high_count == 0:
        _status("fix_proposal", "No HIGH severity issues to fix")
        return {"fix_proposals": [], "fix_results": []}
    _status("fix_proposal", f"Generating fix proposals for {high_count} HIGH severity issues...")
    proposals = prepare_fixes(code_findings, repo_path, groq_key)
    _status("fix_proposal", f"✓ {len(proposals)} fix proposals ready for review")
    return {"fix_proposals": proposals, "fix_results": []}


def human_fix_review_node(state: VulnScanState) -> dict:
    proposals = state.get("fix_proposals", [])
    fix_results = state.get("fix_results", []) or []
    pending = [p for p in proposals if p.get("status") == "pending"]

    if not pending:
        total_fixed = sum(1 for r in fix_results if r.get("status") == "fixed")
        _status("human_fix_review", f"✓ All fixes reviewed — {total_fixed} applied")
        return {"fix_proposals": proposals, "fix_results": fix_results}

    proposal = pending[0]
    total = len(proposals)
    current = total - len(pending) + 1

    print()
    print(f"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"    FIX {current}/{total} — {proposal['test_id']}")
    print(f"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"    File    : {proposal['filename']} (line {proposal['line']})")
    print(f"    Issue   : {proposal['description']}")
    show_diff(proposal["original_snippet"], proposal["fixed_snippet"])

    user_input = interrupt(f"Apply this fix? (yes / no / skip all): ")
    response = str(user_input).strip().lower()

    if response in ("skip all", "skip"):
        for p in proposals:
            if p.get("status") == "pending":
                p["status"] = "skipped"
        _status("human_fix_review", "Skipping all remaining fixes")
        return {"fix_proposals": proposals, "fix_results": fix_results}
    elif response in ("yes", "y"):
        result = apply_approved_fix(proposal)
        proposal["status"] = result["status"]
        fix_results = list(fix_results) + [proposal]
        icon = "✓" if result["status"] == "fixed" else "✗"
        _status("human_fix_review", f"{icon} Fix {'applied' if result['status'] == 'fixed' else 'failed'}")
    else:
        proposal["status"] = "skipped"
        _status("human_fix_review", "↷ Fix skipped")

    return {"fix_proposals": proposals, "fix_results": fix_results}


def report_generator_node(state: VulnScanState) -> dict:
    if not state.get("human_approved"):
        _status("report_generator", "Skipped — not approved")
        return {"markdown_report": None}
    groq_key = os.environ.get("GROQ_API_KEY")
    code_findings = state.get("code_findings", [])
    dep_findings = state.get("dep_findings", [])
    enriched_deps = state.get("cve_data", [])
    fix_results = state.get("fix_results", [])
    target = state.get("target", "unknown")
    critic_feedback = state.get("critic_feedback")
    iteration = state.get("critic_iteration", 0)

    if critic_feedback and critic_feedback.get("verdict") == "needs_revision" and iteration == 1:
        _status("report_generator", "Regenerating with critic feedback...")
        existing_report = state.get("markdown_report", "")
        markdown_report = regenerate_with_feedback(existing_report, critic_feedback, groq_key)
    else:
        _status("report_generator", "Generating report with Groq LLM...")
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

    if fix_results:
        fixed = [f for f in fix_results if f.get("status") == "fixed"]
        skipped = [f for f in fix_results if f.get("status") == "skipped"]
        fix_section = "\n\n## ✅ Fix Agent Summary\n\n"
        fix_section += f"**{len(fixed)} fixes applied, {len(skipped)} skipped.**\n\n"
        if fixed:
            fix_section += "**Applied:**\n"
            for f in fixed:
                fix_section += f"- `{f['filename']}` line {f['line']} — {f['test_id']}: {f['description'][:80]}\n"
        if skipped:
            fix_section += "\n**Skipped:**\n"
            for f in skipped:
                fix_section += f"- `{f['filename']}` line {f['line']} — {f['test_id']}\n"
        markdown_report += fix_section

    _status("report_generator", "✓ Report draft ready — sending to critic")
    return {"markdown_report": markdown_report}


def critic_agent_node(state: VulnScanState) -> dict:
    if not state.get("human_approved") or not state.get("markdown_report"):
        return {"final_report": None}
    groq_key = os.environ.get("GROQ_API_KEY")
    markdown_report = state["markdown_report"]
    target = state.get("target", "unknown")
    output_dir = state.get("output_dir", "./reports")
    iteration = state.get("critic_iteration", 0)

    _status("critic_agent", f"Reviewing report quality (iteration {iteration + 1})...")
    feedback = run_critic(markdown_report, groq_key)
    verdict = feedback.get("verdict", "approved")
    score = feedback.get("score", 0)
    issues = feedback.get("issues", [])

    if verdict == "approved":
        _status("critic_agent", f"✓ Report approved — quality score {score}/10")
    else:
        _status("critic_agent", f"⚠ Issues found (score {score}/10) — {len(issues)} problem(s)")
        for issue in issues[:3]:
            _status("critic_agent", f"  [{issue['type']}] {issue['description'][:70]}")

    critic_section = format_critic_section(feedback, iteration + 1)
    final_markdown = markdown_report + critic_section
    html = convert_to_html(final_markdown, target)
    filepath = save_report(html, output_dir)
    _status("critic_agent", f"✓ Final report saved → {filepath}")

    return {
        "critic_feedback": feedback,
        "critic_iteration": iteration + 1,
        "final_report": filepath
    }


def pr_opener_node(state: VulnScanState) -> dict:
    target = state.get("target", "")
    if not target.startswith("https://github.com/"):
        _status("pr_opener", "Skipping — target is not a GitHub URL")
        return {"pr_url": None}

    fix_results = state.get("fix_results") or []
    fixed = [f for f in fix_results if f.get("status") == "fixed"]
    if not fixed:
        _status("pr_opener", "Skipping — no fixes were applied")
        return {"pr_url": None}

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        _status("pr_opener", "✗ GITHUB_TOKEN not set — skipping PR", error=True)
        return {"pr_url": None}

    repo_path = state.get("repo_path", "")
    final_report = state.get("final_report", "")

    _status("pr_opener", f"Opening PR with {len(fixed)} fix(es)...")
    result = open_pr_with_fixes(
        target_url=target,
        repo_path=repo_path,
        fix_results=fix_results,
        report_path=final_report,
        github_token=github_token
    )

    if repo_path and "vuln_scan_" in repo_path:
        shutil.rmtree(repo_path, ignore_errors=True)
        _status("pr_opener", "Cleaned up temp clone")

    if result.get("success"):
        return {"pr_url": result["url"]}
    else:
        _status("pr_opener", f"✗ PR failed: {result.get('error')}", error=True)
        return {"pr_url": None}


def route_to_fetcher(state: VulnScanState) -> str:
    return "github_fetcher" if state["input_type"] == "github" else "local_reader"


def route_after_fix_review(state: VulnScanState) -> str:
    proposals = state.get("fix_proposals", [])
    pending = [p for p in proposals if p.get("status") == "pending"]
    if pending:
        return "human_fix_review"
    return "report_generator"


def route_after_critic(state: VulnScanState) -> str:
    feedback = state.get("critic_feedback", {})
    iteration = state.get("critic_iteration", 0)
    if feedback.get("verdict") == "needs_revision" and iteration == 1:
        _status("critic_agent", "→ Triggering report revision...")
        return "report_generator"
    return "pr_opener"


def build_graph(checkpointer):
    builder = StateGraph(VulnScanState)

    builder.add_node("router", router_node)
    builder.add_node("github_fetcher", github_fetcher_node)
    builder.add_node("local_reader", local_reader_node)
    builder.add_node("code_scanner", code_scanner_node)
    builder.add_node("dep_scanner", dep_scanner_node)
    builder.add_node("cve_enricher", cve_enricher_node)
    builder.add_node("human_review", human_review_node)
    builder.add_node("fix_proposal", fix_proposal_node)
    builder.add_node("human_fix_review", human_fix_review_node)
    builder.add_node("report_generator", report_generator_node)
    builder.add_node("critic_agent", critic_agent_node)
    builder.add_node("pr_opener", pr_opener_node)

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
    builder.add_edge("human_review", "fix_proposal")
    builder.add_edge("fix_proposal", "human_fix_review")
    builder.add_conditional_edges(
        "human_fix_review",
        route_after_fix_review,
        {"human_fix_review": "human_fix_review", "report_generator": "report_generator"}
    )
    builder.add_edge("report_generator", "critic_agent")
    builder.add_conditional_edges(
        "critic_agent",
        route_after_critic,
        {"report_generator": "report_generator", "pr_opener": "pr_opener"}
    )
    builder.add_edge("pr_opener", END)

    return builder.compile(checkpointer=checkpointer)


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Finder Agent")
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
            "fix_proposals": None,
            "fix_results": None,
            "markdown_report": None,
            "critic_feedback": None,
            "critic_iteration": 0,
            "final_report": None,
            "pr_url": None,
        }

        current_input = initial_state

        while True:
            interrupted = False
            for event in graph.stream(current_input, config=config, stream_mode="updates"):
                if "__interrupt__" in event:
                    interrupted = True
                    interrupt_val = event["__interrupt__"][0].value
                    if "apply" in str(interrupt_val).lower():
                        user_input = input(f"  Apply this fix? (yes / no / skip all): ").strip()
                    else:
                        user_input = input("  Proceed with fix proposals and report generation? (yes/no): ").strip()
                    print()
                    current_input = Command(resume=user_input)
                    break

            if not interrupted:
                final_state = graph.get_state(config)
                result = final_state.values
                break

        fix_results = result.get("fix_results") or []
        fixed_count = sum(1 for f in fix_results if f.get("status") == "fixed")

        if fixed_count > 0:
            print(f"\n  ✓ Auto-fixed {fixed_count} HIGH severity issues")
        if result.get("final_report"):
            print(f"\n  ✓ Report: {result['final_report']}")
        if result.get("pr_url"):
            print(f"\n  ✓ Pull Request opened → {result['pr_url']}\n")
        elif fixed_count > 0:
            print(f"\n  ℹ Set GITHUB_TOKEN to auto-open a PR with these fixes\n")
        else:
            print()


if __name__ == "__main__":
    main()