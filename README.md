# Policy Watch

Policy Watch is a Windows desktop application for organizing, versioning, and distributing policy documents. It is built with Python 3.10+ and PyQt5, stores metadata in SQLite, and manages policy files on disk.

## Key Features

- Maintain a catalog of policies with categories, statuses, and traffic-light review indicators.
- Version policy documents with file integrity checks (SHA-256) and audit logging.
- Track current versions, ratification status, review dates, and notes.
- Filter and search policies by category, status, traffic status, and ratification.
- Distribute selected policies via Microsoft Outlook, with per-recipient audit records.
- Load staff recipient lists from the bundled Access extractor.
- Export audit logs to CSV and verify audit log integrity.
- Configure settings such as policy root folder, review thresholds, and email attachment size limits.
- Backup/export the database with optional policy files in a single zip.

## Requirements

- Windows 10/11 or Windows Server (RDS supported)
- Python 3.10+
- PyQt5
- pywin32 (for Outlook automation)
- Microsoft Outlook profile configured on the host
- Microsoft Access installed (required to run the bundled staff extractor)

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```powershell
$env:PYTHONPATH = "src"
python -m policywatch
```

On first run, you will be prompted to create the default admin password.

## Build (PyInstaller)

```bash
pyinstaller PolicyWatch.spec
```

The executable will be created in `dist/PolicyWatch/PolicyWatch.exe`.

## Data Storage

- The SQLite database is stored in `policywatch.db` under the data directory.
- Default data directory is the current working directory, or the executable directory for PyInstaller builds.
- Override the data directory with `POLICYWATCH_DATA_DIR`.
- Policy files are stored under the configured policy root (Settings → Policy root folder). If unset, the default is `<data_dir>/policies`.

## Email Distribution & Staff Import

- The Policy Distributor tab sends emails through Outlook and logs results in the audit log.
- Staff recipients are loaded by running the bundled Access extractor at `src/policywatch/integrations/staff_details_extractor.accdb` and reading `staff_details.csv`.
- Manual recipient addresses can be added in the UI.

## Backups

Use Settings → Backup/Export to create a zip containing the SQLite database and, optionally, the policy files.

## Notes

- SQLite uses WAL mode and a busy timeout for concurrent access.
- Access integration requires Microsoft Access installed on the host.
- Outlook integration uses COM automation via pywin32.
