# critic_agent.py
# Critic Agent — reviews the generated security report for quality issues
# Checks for: false positives, wrong severity, vague recommendations, missing context

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

CRITIC_SYSTEM_PROMPT = """You are a senior security engineer reviewing a junior analyst's vulnerability report.

Your job is to critically evaluate the report for these specific issues:
1. FALSE POSITIVES — findings that are clearly not real vulnerabilities given the context
2. SEVERITY MISMATCHES — findings rated too high or too low compared to actual risk
3. VAGUE RECOMMENDATIONS — action items that say "fix this" without explaining how
4. MISSING CONTEXT — findings mentioned without explaining why they matter
5. INCOMPLETE COVERAGE — important patterns in the findings that weren't highlighted

Respond in this exact JSON format:
{
  "verdict": "approved" or "needs_revision",
  "score": 1-10,
  "issues": [
    {
      "type": "false_positive" | "severity_mismatch" | "vague_recommendation" | "missing_context" | "incomplete_coverage",
      "description": "specific issue found",
      "suggestion": "how to fix this in the report"
    }
  ],
  "overall_feedback": "2-3 sentence summary of report quality and what to improve"
}

If the report is good quality (score >= 7), set verdict to "approved" even if there are minor issues.
Be specific — reference actual content from the report, not generic feedback.
Return ONLY the JSON, no markdown, no preamble."""


def run_critic(markdown_report: str, groq_api_key: str) -> dict:
    """
    Reviews the markdown report and returns structured feedback.
    Returns: { verdict, score, issues, overall_feedback }
    """
    import json

    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=groq_api_key,
        temperature=0
    )

    try:
        response = llm.invoke([
            SystemMessage(content=CRITIC_SYSTEM_PROMPT),
            HumanMessage(content=f"Please review this security report:\n\n{markdown_report}")
        ])

        raw = response.content.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        feedback = json.loads(raw)
        return feedback

    except json.JSONDecodeError:
        # If LLM didn't return valid JSON, return a safe default
        return {
            "verdict": "approved",
            "score": 6,
            "issues": [],
            "overall_feedback": "Critic agent could not parse response — report saved as-is."
        }
    except Exception as e:
        return {
            "verdict": "approved",
            "score": 6,
            "issues": [],
            "overall_feedback": f"Critic agent error: {e} — report saved as-is."
        }


def regenerate_with_feedback(
    original_report: str,
    critic_feedback: dict,
    groq_api_key: str
) -> str:
    """
    Regenerates the report incorporating critic's feedback.
    Returns improved markdown report.
    """
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=groq_api_key,
        temperature=0
    )

    issues_text = "\n".join([
        f"- [{i['type'].upper()}] {i['description']} → {i['suggestion']}"
        for i in critic_feedback.get("issues", [])
    ])

    response = llm.invoke([
        SystemMessage(content="""You are a security analyst improving a vulnerability report based on peer review feedback.
Rewrite the report addressing all the issues raised. Keep the same structure but fix the problems identified.
Return only the improved markdown report, no preamble."""),
        HumanMessage(content=f"""Here is the original report:

{original_report}

The reviewer found these issues:
{issues_text}

Overall feedback: {critic_feedback.get('overall_feedback', '')}

Please rewrite the report addressing all these issues.""")
    ])

    return response.content.strip()


def format_critic_section(critic_feedback: dict, iteration: int) -> str:
    """Format critic feedback as a markdown section for the HTML report."""
    verdict = critic_feedback.get("verdict", "unknown")
    score = critic_feedback.get("score", 0)
    issues = critic_feedback.get("issues", [])
    overall = critic_feedback.get("overall_feedback", "")

    verdict_icon = "✅" if verdict == "approved" else "⚠️"
    retry_note = " *(after revision)*" if iteration > 1 else ""

    section = f"\n\n---\n\n## 🔍 Critic Review Notes{retry_note}\n\n"
    section += f"**Verdict:** {verdict_icon} {verdict.upper()}  \n"
    section += f"**Quality Score:** {score}/10  \n\n"
    section += f"**Overall:** {overall}\n\n"

    if issues:
        section += "**Issues identified:**\n\n"
        for issue in issues:
            section += f"- **[{issue['type'].replace('_', ' ').title()}]** {issue['description']}\n"
            section += f"  *Suggestion: {issue['suggestion']}*\n\n"

    if verdict != "approved" and iteration >= 2:
        section += "\n> ⚠️ **Note:** This report was flagged by the critic agent after revision. Manual review recommended.\n"

    return section
