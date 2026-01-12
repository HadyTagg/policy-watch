# Policy Watch

Policy Watch is a Windows desktop application for organising, versioning, and distributing policy documents. The application is built with Python 3.11 and PyQt5 and stores metadata in SQLite.

## Requirements

- Windows 10/11 or Windows Server (RDS supported)
- Python 3.11
- Microsoft Access Database Engine driver (for reading `.accdb`)
- Microsoft Outlook profile configured on the host

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
PYTHONPATH=src python -m policywatch
```

On first run, you will be prompted to create the default admin password.

## Build (PyInstaller)

```bash
pyinstaller PolicyWatch.spec
```

The executable will be created in `dist/PolicyWatch/PolicyWatch.exe`.

## Notes

- Application data is stored in root dir by default. Override with `POLICYWATCH_DATA_DIR`.
- SQLite uses WAL mode and a busy timeout for concurrent access.
- Access integration requires the Microsoft Access Database Engine driver.
- Outlook integration uses COM automation.
