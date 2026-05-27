# AntiShield Pro Defender

A Windows Defender-style educational desktop security application built with PySide6.

This version is desktop-only and focuses on one clear workflow: **Scan Center**.
The Scan Center combines:

- MalVisor LightGBM PE malware model
- YARA rules
- Hash checks
- Script checks
- PE import / entropy checks
- Quarantine
- Plain-language reports

Additional tabs provide:

- Network audit
- USB scan
- Startup item scan
- Scheduled task scan
- Process behavior scan
- Memory/process risk scan
- Quarantine manager
- YARA rule validation
- HTML/PDF reports

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python desktop_app.py
```

## MalVisor model

Place the model here:

```text
models/malvisor/malware_model.pkl
```

You can use the included downloader:

```powershell
.\download_malvisor_model.ps1
```

Security note: `.pkl` files can execute code when loaded. Only use model files from sources you trust.

## Notes

- The app is defensive and educational.
- It never executes scanned files.
- Network audit uses local endpoint connection information through `psutil`; it does not attack or exploit devices.
- Memory scan is a safe process/memory-risk audit; it does not dump process memory.


Network AI architecture
-----------------------
The Network tab now includes:

- Fast rule-based endpoint network audit using psutil.
- Gemini AI network explanation when GEMINI_API_KEY is configured.
- Optional CICIDS2017-style AI integration. It only runs when a compatible flow model and feature schema are added under models/cicids/.

The optional CICIDS AI is not run on raw psutil connection rows unless its feature schema matches the available endpoint summary features. For standard CICIDS2017 models, use a real flow extractor first. See NETWORK_AI_README.md.
