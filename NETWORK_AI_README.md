AntiShield Network Audit + Gemini + Optional CICIDS AI
======================================================

This project uses three network layers:

1. Fast rule-based Network Audit
--------------------------------
This is enabled by default. It uses psutil to list current TCP/UDP connections,
listening ports, processes, local/remote addresses, and simple risk signals.
It does not sniff packets and does not upload data.

2. Gemini AI Network Report
---------------------------
If GEMINI_API_KEY is configured, the network audit is summarized in simple
language for non-technical users. If Gemini is not configured, the app uses a
local fallback explanation.

Set key in PowerShell:
    $env:GEMINI_API_KEY="your_key_here"

3. Optional CICIDS2017 AI
-------------------------
This is disabled by default. CICIDS-style models usually require packet-flow
features, not just active connection rows. To enable it later, add:

    models/cicids/cicids_model.joblib
    models/cicids/feature_columns.json

The feature_columns file must exactly match the model's expected input columns.
For real CICIDS models, generate flow CSV records first using tools such as:
CICFlowMeter, Zeek, Suricata eve.json, or another flow extractor.

The app will safely show "Network AI not run" until a compatible model and
feature schema are provided.
