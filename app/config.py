from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "antishield_pro.db"
RULES_DIR = BASE_DIR / "app" / "rules"
REPORTS_DIR = BASE_DIR / "reports"
QUARANTINE_DIR = BASE_DIR / "quarantine"
SCAN_TARGETS_DIR = BASE_DIR / "scan_targets"
MODELS_DIR = BASE_DIR / "models"
MALVISOR_MODEL_PATH = MODELS_DIR / "malvisor" / "malware_model.pkl"

for directory in [RULES_DIR, REPORTS_DIR, QUARANTINE_DIR, SCAN_TARGETS_DIR, MODELS_DIR / "malvisor"]:
    directory.mkdir(parents=True, exist_ok=True)

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".msi"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".py", ".sh"}
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

RISK_CLEAN_MAX = 24
RISK_REVIEW_MAX = 54
RISK_MALICIOUS_MAX = 79

KNOWN_BAD_HASHES = {
    # EICAR antivirus test file SHA-256
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}

IGNORED_SCAN_DIRS = {
    ".git", ".idea", ".mypy_cache", ".pytest_cache", ".venv", "venv", "env",
    "__pycache__", "node_modules", "reports", "quarantine", "models", "tools",
}

# Avoid self-detection when users scan the project folder itself.
PROJECT_SOURCE_DIRS = {"app", "rules"}
