import os
import re
from typing import List, Dict, Any

import streamlit as st
from dotenv import load_dotenv
from groq import Groq
from hindsight_client import Hindsight


# ============================================================
# CONFIG
# ============================================================

load_dotenv()

HINDSIGHT_API_KEY = os.getenv("HINDSIGHT_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

HINDSIGHT_BASE_URL = "https://api.hindsight.vectorize.io"
BANK_ID = "threatmemory"
GROQ_MODEL = "openai/gpt-oss-120b"


# ============================================================
# PAGE
# ============================================================

st.set_page_config(
    page_title="ThreatMemory",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# CLIENTS
# ============================================================


def get_hindsight():
    if not HINDSIGHT_API_KEY:
        raise RuntimeError("HINDSIGHT_API_KEY is missing from .env")

    client = Hindsight(
        base_url=HINDSIGHT_BASE_URL,
        api_key=HINDSIGHT_API_KEY,
    )

    # Create bank if it does not already exist.
    try:
        client.create_bank(
            bank_id=BANK_ID,
            name="ThreatMemory Security Cases",
        )
    except Exception:
        # Bank probably already exists.
        pass

    return client


@st.cache_resource
def get_groq():
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY is missing from .env")

    return Groq(api_key=GROQ_API_KEY)


# ============================================================
# HINDSIGHT
# ============================================================

def recall_memories(alert: str) -> List[Dict[str, Any]]:
    """
    Retrieve relevant historical security cases from Hindsight.
    """

    hindsight = get_hindsight()

    result = hindsight.recall(
        bank_id=BANK_ID,
        query=alert,
    )

    memories = []

    if not result or not getattr(result, "results", None):
        return memories

    for item in result.results[:5]:
        text = getattr(item, "text", None)

        if text:
            memories.append(
                {
                    "text": text,
                }
            )

    return memories


def save_analyst_decision(
    alert: str,
    ai_recommendation: str,
    analyst_verdict: str,
    reason: str,
):
    """
    Store the analyst's final decision as a new memory.
    """

    hindsight = get_hindsight()

    memory = f"""
ThreatMemory analyst decision.

Security Alert:
{alert}

AI Recommendation:
{ai_recommendation}

Analyst Final Verdict:
{analyst_verdict}

Analyst Reason:
{reason}

This case should be remembered for future security-alert investigations.
"""

    hindsight.retain(
        bank_id=BANK_ID,
        content=memory.strip(),
    )


# ============================================================
# GROQ
# ============================================================

def analyze_alert(
    alert: str,
    memories: List[Dict[str, Any]],
    memory_enabled: bool,
) -> Dict[str, Any]:

    groq = get_groq()

    if memory_enabled and memories:
        memory_text = "\n\n".join(
            f"PAST CASE {i + 1}:\n{m['text']}"
            for i, m in enumerate(memories)
        )

        context = f"""
Historical security cases retrieved from Hindsight:

{memory_text}
"""

    elif memory_enabled:
        context = """
No relevant historical cases were found in Hindsight.
"""

    else:
        context = """
Memory is OFF.

Do not use any historical cases.
Analyze this alert only from the information contained in the alert itself.
"""

    prompt = f"""
You are ThreatMemory, an AI assistant for a cybersecurity analyst.

Your job is to help an analyst triage a security alert.

IMPORTANT:
- You are decision support, not an autonomous security system.
- Never claim certainty when the evidence is insufficient.
- Do not invent facts or details.
- Treat the CURRENT SECURITY ALERT and HISTORICAL CASES as separate sources of evidence.
- Never describe a fact from the current alert as a historical fact unless that fact is explicitly present in a retrieved historical case.
- Never claim that multiple historical cases contain the same detail unless multiple retrieved cases actually contain that detail.
- If only one historical case contains a specific detail, refer to it as one prior case, not multiple cases.
- Do not treat multiple retrieved memory records as multiple independent incidents; they may describe the same historical investigation.
- When historical cases are provided, use them as context and clearly distinguish past evidence from current-alert evidence.
- Memory should influence the recommendation naturally.
- Do not blindly copy an old decision.
- The analyst always makes the final decision.

{context}

CURRENT SECURITY ALERT:
{alert}

Return your answer using EXACTLY this structure:

RECOMMENDATION: [FALSE ALARM / REAL THREAT / NEEDS INVESTIGATION]

CONFIDENCE: [LOW / MEDIUM / HIGH]

REASON:
[2-4 concise sentences explaining the recommendation]

NEXT STEPS:
1. [first practical investigation step]
2. [second practical investigation step]
3. [third practical investigation step]

Be concise and suitable for a security analyst.
"""

    response = groq.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {
                "role": "system",
                "content": "You are a careful cybersecurity alert-triage assistant.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        temperature=0.2,
        max_tokens=700,
    )

    text = response.choices[0].message.content or ""

    return parse_ai_response(text)


# ============================================================
# RESPONSE PARSER
# ============================================================

def parse_ai_response(text: str) -> Dict[str, Any]:

    recommendation_match = re.search(
        r"RECOMMENDATION:\s*(.*)",
        text,
        re.IGNORECASE,
    )

    confidence_match = re.search(
        r"CONFIDENCE:\s*(.*)",
        text,
        re.IGNORECASE,
    )

    reason_match = re.search(
        r"REASON:\s*(.*?)(?=\n\s*NEXT STEPS:|$)",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    steps_match = re.search(
        r"NEXT STEPS:\s*(.*)",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    recommendation = (
        recommendation_match.group(1).strip()
        if recommendation_match
        else "NEEDS INVESTIGATION"
    )

    confidence = (
        confidence_match.group(1).strip()
        if confidence_match
        else "LOW"
    )

    reason = (
        reason_match.group(1).strip()
        if reason_match
        else text.strip()
    )

    steps_text = (
        steps_match.group(1).strip()
        if steps_match
        else ""
    )

    steps = []

    for line in steps_text.splitlines():
        cleaned = re.sub(r"^\s*\d+[\.\)]\s*", "", line).strip()

        if cleaned:
            steps.append(cleaned)

    return {
        "recommendation": recommendation,
        "confidence": confidence,
        "reason": reason,
        "steps": steps[:3],
        "raw": text,
    }


# ============================================================
# SAMPLE ALERTS
# ============================================================

SAMPLE_ALERTS = {
    "VPN login alert": """Security Alert:

36 failed authentication attempts against payroll@company.com
between 01:50 AM and 02:05 AM.

Source IP: 185.20.4.21
User: payroll@company.com
Location: Hyderabad
Time: 01:50 AM - 02:05 AM
Event: Multiple failed authentication attempts

The employee was working remotely.
The source appears to be associated with the organization's
remote-access infrastructure.
No successful authentication was observed.
""",

    "Credential stuffing attack": """Security Alert:
Large-scale credential stuffing detected.

412 user accounts received failed login attempts within 8 minutes.
Attempts originated from 37 previously unseen external IP addresses.
Several accounts subsequently received successful logins.

Source: Identity Provider
Severity: Critical
""",

    "Large backup transfer": """Security Alert:
Unusual outbound data transfer detected at 02:07 AM.

Source host: backup-server-03
Destination: corporate cloud backup storage
Transferred: 184 GB
Process: scheduled-backup
""",

    "New country login": """Security Alert:
Successful login detected for employee account from a new country.

User: employee@company.com
Previous country: India
Current country: Singapore
Time: 04:22 AM
Device: Previously unseen
""",
}


# ============================================================
# SESSION STATE
# ============================================================

if "analysis" not in st.session_state:
    st.session_state.analysis = None

if "memories" not in st.session_state:
    st.session_state.memories = []

if "last_alert" not in st.session_state:
    st.session_state.last_alert = ""

if "saved" not in st.session_state:
    st.session_state.saved = False


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ ThreatMemory")

st.markdown(
    """
### Security alert triage that remembers what happened before.

ThreatMemory helps security analysts investigate alerts by remembering
how similar alerts were handled previously.
"""
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("ThreatMemory")

    memory_enabled = st.toggle(
        "🧠 Hindsight Memory",
        value=True,
    )

    if memory_enabled:
        st.success("Memory ON")
        st.caption(
            "The AI can retrieve relevant historical investigations "
            "from Hindsight."
        )
    else:
        st.warning("Memory OFF")
        st.caption(
            "The AI analyzes the alert without historical context."
        )

    st.divider()

    st.subheader("Demo Alerts")

    selected_sample = st.selectbox(
        "Choose a sample alert",
        ["None"] + list(SAMPLE_ALERTS.keys()),
    )

    st.divider()

    st.caption(
        "Recommendation only. The security analyst makes the final decision."
    )


# ============================================================
# ALERT INPUT
# ============================================================

st.subheader("1. Security Alert")

default_alert = ""

if selected_sample != "None":
    default_alert = SAMPLE_ALERTS[selected_sample]

alert = st.text_area(
    "Paste the security alert here",
    value=default_alert,
    height=190,
    placeholder=(
        "Example: Multiple failed logins detected from "
        "an unfamiliar IP address..."
    ),
)

analyze_clicked = st.button(
    "🔍 Analyze Alert",
    type="primary",
    use_container_width=True,
)


# ============================================================
# ANALYZE
# ============================================================

if analyze_clicked:

    if not alert.strip():
        st.error("Please paste a security alert first.")

    else:

        st.session_state.saved = False

        with st.spinner("Investigating alert..."):

            try:

                # ------------------------------------------------
                # MEMORY
                # ------------------------------------------------

                if memory_enabled:
                    memories = recall_memories(alert)
                else:
                    memories = []

                # ------------------------------------------------
                # AI
                # ------------------------------------------------

                analysis = analyze_alert(
                    alert=alert,
                    memories=memories,
                    memory_enabled=memory_enabled,
                )

                st.session_state.analysis = analysis
                st.session_state.memories = memories
                st.session_state.last_alert = alert

            except Exception as e:

                st.error(
                    "Something went wrong while analyzing the alert."
                )

                st.exception(e)


# ============================================================
# RESULTS
# ============================================================

if st.session_state.analysis:

    analysis = st.session_state.analysis
    memories = st.session_state.memories

    st.divider()

    st.subheader("2. AI Investigation")

    # ----------------------------------------------------------
    # TOP METRICS
    # ----------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Recommendation",
            analysis["recommendation"],
        )

    with col2:
        st.metric(
            "Confidence",
            analysis["confidence"],
        )

    with col3:
        st.metric(
            "Past Cases Used",
            len(memories),
        )

    # ----------------------------------------------------------
    # REASON
    # ----------------------------------------------------------

    st.markdown("### Why?")

    st.info(analysis["reason"])

    # ----------------------------------------------------------
    # NEXT STEPS
    # ----------------------------------------------------------

    st.markdown("### Recommended Next Steps")

    if analysis["steps"]:

        for step in analysis["steps"]:
            st.markdown(f"- {step}")

    else:

        st.markdown(
            "- Review authentication and network logs."
        )

    # ----------------------------------------------------------
    # HINDSIGHT MEMORY
    # ----------------------------------------------------------

    if memory_enabled:

        st.markdown("### 🧠 Based on These Past Cases")

        if memories:

            st.caption(
                f"Hindsight retrieved {len(memories)} relevant historical cases."
            )

            for i, memory in enumerate(memories[:5]):

                with st.expander(
                    f"Past Investigation #{i + 1}"
                ):
                    st.write(memory["text"])

        else:

            st.info(
                "No relevant historical cases were found. "
                "This recommendation is based on the current alert."
            )

    else:

        st.markdown("### 🧠 Hindsight Memory")

        st.info(
            "Memory is OFF. No historical cases were provided to the AI."
        )


    # ========================================================
    # ANALYST DECISION
    # ========================================================

    st.divider()

    st.subheader("3. Analyst Decision")

    st.caption(
        "The analyst makes the final decision. "
        "Your decision will become future memory."
    )

    decision = st.radio(
        "Final verdict",
        [
            "FALSE ALARM",
            "REAL THREAT",
            "NEEDS INVESTIGATION",
        ],
        horizontal=True,
    )

    reason = st.text_input(
        "Why did you choose this verdict?",
        placeholder="Example: Source IP belongs to our corporate VPN range.",
    )

    save_clicked = st.button(
        "💾 Save Analyst Decision to Hindsight",
        use_container_width=True,
    )

    if save_clicked:

        if not reason.strip():
            st.warning(
                "Please provide a short reason before saving."
            )

        else:

            try:

                save_analyst_decision(
                    alert=st.session_state.last_alert,
                    ai_recommendation=analysis["recommendation"],
                    analyst_verdict=decision,
                    reason=reason,
                )

                st.session_state.saved = True

                st.success(
                    "Analyst decision saved to Hindsight. "
                    "Future investigations can learn from this case."
                )

            except Exception as e:

                st.error(
                    "Could not save the analyst decision to Hindsight."
                )

                st.exception(e)


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "ThreatMemory • AI-assisted security alert triage • "
    "Recommendation only — analyst decides."
)