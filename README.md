# RealAntivirus

A modern, GUI-based antivirus simulator with a clean, professional interface. It scans folders, flags suspicious files by heuristics, supports quarantine/restore/delete, shows reports, and has a live Dark/Light theme toggle.

## 🎨 UI Highlights

- 🌑/☀️ **Dark/Light Toggle** in the top bar (instant theme switch)
- 🧭 **Sidebar Navigation**: Dashboard, Scan, Quarantine, Reports, Settings
- 🛡️ **Dashboard**: Protection status badge, quick actions, recent activity
- 📊 **Scan View**: Quick/Full/Custom modes, progress and live results
- 📦 **Quarantine**: Table view with Restore/Delete selected items
- 📝 **Reports**: Log viewer with Filter and Export
- 🎨 **Color-coded Results**: info (blue), warning (orange), error (red), complete (green)

## Features

- 🔍 **Directory Scanning**: Recursively scans directories for suspicious files
- 🛡️ **Suspicious Extension Detection**: Detects files with potentially harmful extensions (.exe, .dll, .bat, .vbs, .ps1, .sh, .pyc)
- 🔐 **File Hashing**: Calculates SHA-256 hashes for file integrity verification
- 📦 **Quarantine System**: Safely moves suspicious files to a quarantine folder with metadata (restore supported)
- 🗑️ **Delete Function**: Permanently removes suspicious files (with double confirmation)
- 📊 **Progress Tracking**: Real-time progress bar and detailed logging
- 📝 **Comprehensive Logging**: All actions are logged to `scan_log.txt`
- 🧭 **Sidebar UI** with top bar actions and status
- 🌑/☀️ **Dark/Light themes** with live toggle

## Requirements

- Python 3.8 or higher
- tkinter (usually comes with Python)

## Installation

### Option 1: Quick Start (Recommended)

1. Download or clone this repository
2. Double-click `run_antivirus.bat` to start the application

### Option 2: Using Advanced Launcher

1. Download or clone this repository
2. Double-click `run_antivirus_advanced.bat`
3. Use the menu to:
   - Check if Python is installed correctly
   - Install dependencies
   - Run the scanner
   - View logs

### Option 3: Run from Command Line

```bash
python antivirus_scanner.py
```

## Screenshots

Place your screenshots in this section (optional):
- Dashboard (dark)
- Scan view (dark)
- Quarantine actions (dark)
- Reports + Export (light)

## Usage

1. **Launch the Application**
   - Double-click `run_antivirus.bat`, or
   - Run `python antivirus_scanner.py`
   - The app opens on the Dashboard (default theme: Dark)

2. **Scan for Threats**
   - Go to Scan in the sidebar
   - Choose a mode: Quick / Full / Custom (optional)
   - Click "Select Directory to Scan", pick a folder
   - Watch the progress bar and live results

3. **Handle Suspicious Files**
   - If suspicious files are found, you can:
     - Use "Quarantine All" or "Delete All" from the Scan view, or
     - Open Quarantine and use "Restore Selected" / "Delete Selected"

4. **Review Results**
   - Results pane shows color-coded entries
   - Reports view displays the full log (Filter + Export)
   - Quarantine view shows metadata for each item

## Files Created

- `scan_log.txt` - Complete scan history and logs
- `quarantine/` - Folder containing quarantined files
- `quarantine_metadata.json` - Metadata about quarantined files

## Safety Features

- ✅ Confirmation dialogs before quarantine/delete
- ✅ Double confirmation for permanent deletion
- ✅ Detailed logging of all actions
- ✅ Quarantine metadata preservation
- ✅ Color-coded results (info, warning, error, complete)
- ✅ Protective confirmation warnings for destructive actions
- ✅ Read-only quarantine viewer with full metadata

## Customization

### Add More Suspicious Extensions

Edit `antivirus_scanner.py` and modify the `SUSPICIOUS_EXTENSIONS` set:

```python
SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.vbs', '.ps1', '.sh', '.pyc', '.msi', '.scr'}
```

### Change Log File Location

Modify the `LOG_FILE` constant:

```python
LOG_FILE = 'my_custom_log.txt'
```

## Quarantine System

Quarantined files are stored in the `quarantine` folder with:
- Original file name and path
- Timestamp of quarantine
- File hash (SHA-256)
- File size
- Reason for quarantine

All this metadata is saved in `quarantine_metadata.json` for easy recovery or review.

## Restore Quarantined Files

Use the Quarantine view:
1. Select one or more rows
2. Click "Restore Selected" to move them back to their original locations
3. Or click "Delete Selected" to permanently remove the quarantined copies

## Troubleshooting

### Python not found
- Install Python from https://www.python.org/
- Make sure to check "Add Python to PATH" during installation
- Restart your computer after installation

### tkinter not available
- On Linux: Install tkinter with `sudo apt-get install python3-tk`
- On macOS: tkinter should come with Python
- On Windows: tkinter should come with Python

### Permission errors
- Run the script as administrator if scanning protected directories
- Some files may be in use by other programs

## Warning

⚠️ **USE WITH CAUTION**: This tool permanently deletes files when using the "Delete All" function. Only use it if you're certain about the files being scanned. Always review suspicious files before deleting them.

⚠️ The scanner uses heuristics (extensions, hashing) for demonstration purposes. It is not a replacement for professional antivirus software.

## License

This is a demonstration/educational tool. Use at your own risk.

## Version History

### Latest (Current)
- ✨ New sidebar + dashboard UI
- 🌑/☀️ Live Dark/Light theme toggle in the top bar
- 🧭 Dashboard quick actions; status badge and recent activity
- 📦 Quarantine actions: Restore/Delete selected; metadata-driven
- 📝 Reports: Filter + Export log file
- 🧭 Polished styling, icons, and layouts

### Previous Features
- Directory scanning with progress tracking
- SHA-256 file hashing
- Quarantine system with metadata
- Comprehensive logging

## Author

Created as a demonstration of file integrity scanning and quarantine systems with a focus on user experience and modern UI design.

