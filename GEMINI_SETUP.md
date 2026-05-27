# Gemini AI reporting setup

This patch adds Gemini AI reporting for:

- File scan reports
- Network audit reports

The app still works without Gemini. If Gemini is missing or no API key is configured, it uses a local fallback report.

## Install

```powershell
python -m pip install google-genai
```

## Set API key

Temporary for the current terminal:

```powershell
$env:GEMINI_API_KEY="your_key_here"
python desktop_app.py
```

Permanent:

```powershell
setx GEMINI_API_KEY "your_key_here"
```

Then close and reopen PowerShell.

Optional model override:

```powershell
$env:GEMINI_MODEL="gemini-2.0-flash"
```

## Files added / modified

- `app/gemini_reporter.py`: Gemini + local fallback reports for scan and network.
- `app/reports.py`: scan reports now use Gemini when available.
- `desktop_app.py`: network audit now generates an AI network report.
- `requirements.txt`: added `google-genai`.
