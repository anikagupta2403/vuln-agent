# Vulnerability Finder Agent

A LangGraph-based security agent that scans Python repositories for vulnerabilities, proposes human-approved fixes, and opens a GitHub Pull Request — all powered by free tooling.

## What it does

Point it at a GitHub URL or a local folder. It clones the repo, runs static analysis, checks dependencies, enriches findings with CVE severity data, proposes targeted fixes one-by-one for human approval, generates an LLM-reviewed security report, and opens a PR with the approved fixes.

```
Input (GitHub URL or local path)
  → Router            detects input type
  → Fetcher           clones repo or validates local path
  → Code Scanner      bandit SAST analysis
  → Dep Scanner       pip-audit dependency check
  → CVE Enricher      OSV.dev severity + patch data
  → Human Review      pause — show findings summary, ask to proceed
  → Fix Proposal      LLM generates fix for each HIGH severity issue
  → Human Fix Review  pause — show before/after diff, approve each fix individually
  → Report Generator  Groq LLaMA 3 writes the security report
  → Critic Agent      second LLM reviews report quality, triggers revision if needed
  → PR Opener         commits fixes to a new branch, opens GitHub Pull Request
  → findings.html     saved to ./reports/
```

## Stack

| Tool | Purpose |
|------|---------|
| LangGraph | Agent graph framework — state, nodes, edges, human-in-the-loop |
| bandit | Python static analysis (SAST) |
| pip-audit | Dependency CVE checking |
| OSV.dev API | CVE severity + patch data (no key needed) |
| Groq (LLaMA 3) | LLM for fix generation, report writing, critic review |
| GitHub REST API | Branch creation, file commits, PR opening |

## Setup

### 1. Install dependencies

```bash
pip install langgraph langchain-core langchain-groq langchain-community langgraph-checkpoint-sqlite bandit pip-audit requests markdown
```

### 2. Get a free Groq API key

Sign up at [console.groq.com](https://console.groq.com/keys) — no credit card required.

### 3. Get a GitHub Personal Access Token

Go to [github.com/settings/tokens/new](https://github.com/settings/tokens/new) → check **repo** scope → generate.

### 4. Set environment variables

**PowerShell (Windows):**
```powershell
$env:GROQ_API_KEY="your-groq-key-here"
$env:GITHUB_TOKEN="your-github-token-here"
```

**macOS / Linux:**
```bash
export GROQ_API_KEY="your-groq-key-here"
export GITHUB_TOKEN="your-github-token-here"
```

## Usage

```bash
# Scan a GitHub repo
python agent.py --target https://github.com/your-username/your-repo

# Scan a local folder
python agent.py --target ./my-project

# Custom output directory
python agent.py --target https://github.com/org/repo --output ./reports
```

## Example run

```
╔══════════════════════════════════════════╗
║      Vulnerability Finder Agent          ║
╚══════════════════════════════════════════╝
  Target : https://github.com/anikagupta2403/vulpy

  › [router] → GitHub URL detected
  › [github_fetcher] ✓ Cloned successfully
  › [code_scanner] ✓ 51 code issues found
  › [dep_scanner] ✓ 0 vulnerable dependencies found
  › [cve_enricher] No dependency findings — skipping OSV lookup

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    FINDINGS SUMMARY
    Code issues total   : 51
      High              : 4  |  Medium : 36  |  Low : 11
    Dep vulnerabilities : 0
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Proceed with fix proposals and report generation? (yes/no): yes

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    FIX 1/4 — B201
    File : vulpy.py (line 55)
    Issue: Flask debug=True — exposes Werkzeug debugger

    ┌─ CURRENT CODE ──────────────────────────
    │  app.run(debug=True, host='127.0.1.1', port=5000)
    ├─ PROPOSED FIX ──────────────────────────
    │  app.run(debug=False, host='127.0.1.1', port=5000)
    └─────────────────────────────────────────

  Apply this fix? (yes / no / skip all): yes
  › [human_fix_review] ✓ Fix applied
  ... (4 fixes total)

  › [report_generator] ✓ Report draft ready
  › [critic_agent] ✓ Report approved — quality score 8/10
  › [pr_opener] ✓ PR opened → https://github.com/anikagupta2403/vulpy/pull/1

  ✓ Auto-fixed 4 HIGH severity issues
  ✓ Report: ./reports/findings_20260707_005548.html
  ✓ Pull Request opened → https://github.com/anikagupta2403/vulpy/pull/1
```

## Agent architecture

```
START
  │
  ▼
router ──────────────────────────────┐
  │ (github)                         │ (local)
  ▼                                  ▼
github_fetcher               local_reader
  │                                  │
  └──────────────┬───────────────────┘
                 ▼
           code_scanner
                 │
           dep_scanner
                 │
           cve_enricher
                 │
           human_review ◄── [INTERRUPT: proceed?]
                 │
           fix_proposal (LLM generates fixes)
                 │
     ┌─── human_fix_review ◄── [INTERRUPT: apply this fix?]
     │           │
     └───────────┘ (loops per fix)
                 │
         report_generator
                 │
           critic_agent ──► report_generator (if revision needed)
                 │
            pr_opener
                 │
               END
```

## Key features

**Human-in-the-loop** — powered by LangGraph's `interrupt()`. The graph pauses twice: once after scanning (proceed?), then once per proposed fix (apply this fix?). You see a before/after diff for every change before it's applied.

**Fix agent** — targets HIGH severity bandit findings (B201, B608, B105, B106, B113, B310). Uses Groq LLaMA 3 to generate minimal, targeted patches.

**Critic agent** — a second LLM pass that reviews the generated report for false positives, severity mismatches, and vague recommendations. Triggers one revision cycle if quality score is below threshold. Review notes are visible in the final HTML report.

**End-to-end PR** — creates a new branch, commits only the fixed files, and opens a properly described PR via the GitHub REST API.

## Project structure

```
vuln-agent/
├── agent.py          # Main graph + CLI entry point
├── tools.py          # GitHub fetcher, local reader, bandit + pip-audit wrappers
├── enricher.py       # OSV.dev CVE enricher + Groq report generator
├── fix_agent.py      # Fix proposal generation + file patching
├── critic_agent.py   # Report quality review + revision
├── pr_opener.py      # GitHub branch + commit + PR via REST API
├── reports/          # Generated HTML reports (auto-created)
└── README.md
```

## Scope

Python codebases only. Web and network scanning are out of scope — this keeps the agent focused and results accurate. Fix agent targets HIGH severity findings only; MEDIUM findings are reported but not auto-patched.

## Notes

- No GitHub token needed for scanning public repos (only for opening PRs)
- OSV.dev enrichment is capped at 20 findings to avoid timeouts
- Critic agent triggers one revision cycle maximum
- If a repo has no `requirements.txt`, pip-audit is skipped cleanly