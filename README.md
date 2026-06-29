# Vulnerability Finder Agent

A LangGraph-based security agent that scans Python repositories for vulnerabilities — both in the code itself and in its dependencies — and produces a formatted HTML report.

## What it does

Point it at a GitHub URL or a local folder. It clones the repo (if needed), runs static analysis with bandit, checks dependencies with pip-audit, enriches findings with CVE severity data from OSV.dev, and hands everything to an LLM to write a readable security report.

```
Input (GitHub URL or local path)
  → Router           detects input type
  → Fetcher          clones repo or validates local path
  → Code Scanner     bandit static analysis
  → Dep Scanner      pip-audit dependency check
  → CVE Enricher     OSV.dev severity + patch data
  → Report Generator Groq LLaMA 3 writes the report
  → findings.html    saved to ./reports/
```

## Stack

| Tool | Purpose |
|------|---------|
| LangGraph | Agent graph framework |
| bandit | Python static analysis (SAST) |
| pip-audit | Dependency CVE checking |
| OSV.dev API | CVE severity + patch data (no key needed) |
| Groq (LLaMA 3) | LLM report generation (free) |

## Setup

### 1. Install dependencies

```bash
pip install langgraph langchain-core langchain-groq langchain-community bandit pip-audit requests markdown
```

### 2. Get a free Groq API key

Sign up at [console.groq.com](https://console.groq.com/keys) — no credit card required.

### 3. Set your API key

**PowerShell (Windows):**
```powershell
$env:GROQ_API_KEY="your-key-here"
```

**macOS / Linux:**
```bash
export GROQ_API_KEY="your-key-here"
```

## Usage

```bash
# Scan a GitHub repo
python agent.py --target https://github.com/fportantier/vulpy

# Scan a local folder
python agent.py --target ./my-project

# Custom output directory
python agent.py --target https://github.com/org/repo --output ./reports
```

Open the generated HTML file in your browser to read the report.

## Example output

```
╔══════════════════════════════════════════╗
║      Vulnerability Finder Agent          ║
╚══════════════════════════════════════════╝
  Target : https://github.com/fportantier/vulpy
  Output : ./reports

  › [router] → GitHub URL detected
  › [github_fetcher] ✓ Cloned successfully
  › [code_scanner] ✓ 51 code issues found
  › [dep_scanner] ✓ 0 vulnerable dependencies found
  › [cve_enricher] No dependency findings — skipping OSV lookup
  › [report_generator] ✓ Report saved → ./reports/findings_20260630_022350.html

  ✓ Scan complete!
  ✓ Open your report: ./reports/findings_20260630_022350.html
```

## Project structure

```
cyware/
├── agent.py       # Main graph + CLI entry point
├── tools.py       # GitHub fetcher, local reader, bandit + pip-audit wrappers
├── enricher.py    # OSV.dev CVE enricher + LLM report generator
├── reports/       # Generated HTML reports (auto-created)
└── README.md
```

## Scope

Python codebases only. Web and network scanning are out of scope by design — this keeps the agent focused and the results accurate.

## Notes

- GitHub token is not required for public repos
- OSV.dev enrichment is capped at 20 findings to avoid timeouts
- Bandit will flag subprocess usage as LOW severity — this is expected in tool wrappers
- If a repo has no `requirements.txt`, pip-audit is skipped cleanly (not an error)
