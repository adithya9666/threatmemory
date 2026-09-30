# ThreatMemory

### Security Alert Triage That Learns From Analyst Experience

ThreatMemory is an AI-powered security alert triage assistant that uses **Hindsight memory** to learn from previous security investigations and analyst decisions.

Security teams repeatedly investigate similar alerts, especially false positives. ThreatMemory retrieves relevant past cases before analyzing a new alert, giving the analyst context about what happened before.

The analyst remains in control. Every new analyst decision can become future memory, allowing the system to improve over time.

## 🚀 Live Demo

[Open ThreatMemory](https://threatmemory-f2kdfnwvpefa9isiqucgxv.streamlit.app)
---

## The Problem

Security analysts receive large numbers of alerts every day.

Many alerts are recurring patterns:

- Corporate VPN activity
- Automated backup jobs
- Business travel
- Repeated authentication failures
- Known attack patterns

Without organizational memory, analysts may repeatedly investigate the same situations from scratch.

ThreatMemory addresses this by giving the AI access to the organization's previous investigation experience.

---

## How It Works

```text
Security Alert
      ↓
Hindsight Recall
      ↓
Relevant Past Cases
      ↓
AI Triage Recommendation
      ↓
Analyst Decision
      ↓
Hindsight Retain
      ↓
Better Future Recommendations
