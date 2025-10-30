import os
import hashlib
import logging
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import json
import shutil
from datetime import datetime
from pathlib import Path

# --- Constants ---
SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.vbs', '.ps1', '.sh', '.pyc'}
LOG_FILE = 'scan_log.txt'
QUARANTINE_FOLDER = 'quarantine'
QUARANTINE_METADATA = 'quarantine_metadata.json'

# --- Core Logic ---

def setup_logging():
    """Configures the logging system to write to a file and the console."""
    # We remove any existing handlers to avoid duplicate logs on repeated scans
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler() # Also print to console/terminal
        ]
    )

def get_file_hash(filepath, block_size=65536):
    """Calculates the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except IOError as e:
        logging.warning(f"Could not read file {filepath}: {e}")
        return None
    except PermissionError as e:
        logging.warning(f"Permission denied for file {filepath}: {e}")
        return None

def ensure_quarantine_folder():
    """Creates the quarantine folder if it doesn't exist."""
    if not os.path.exists(QUARANTINE_FOLDER):
        os.makedirs(QUARANTINE_FOLDER)
        logging.info(f"Created quarantine folder: {QUARANTINE_FOLDER}")

def load_quarantine_metadata():
    """Loads the quarantine metadata JSON file."""
    if os.path.exists(QUARANTINE_METADATA):
        try:
            with open(QUARANTINE_METADATA, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading quarantine metadata: {e}")
            return {}
    return {}

def save_quarantine_metadata(metadata):
    """Saves the quarantine metadata to a JSON file."""
    try:
        with open(QUARANTINE_METADATA, 'w') as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving quarantine metadata: {e}")

def quarantine_file(filepath, suspicious_files_count):
    """Moves a file to the quarantine folder and saves metadata."""
    try:
        ensure_quarantine_folder()
        
        # Get file info before moving
        filename = os.path.basename(filepath)
        file_hash = get_file_hash(filepath)
        file_size = os.path.getsize(filepath)
        quarantine_time = datetime.now().isoformat()
        
        # Create a unique quarantine filename to avoid conflicts
        file_extension = os.path.splitext(filename)[1]
        safe_filename = os.path.basename(os.path.normpath(filepath)).replace(os.sep, '_')
        quarantine_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_filename}"
        quarantine_path = os.path.join(QUARANTINE_FOLDER, quarantine_filename)
        
        # Move file to quarantine
        shutil.move(filepath, quarantine_path)
        
        # Save metadata
        metadata = load_quarantine_metadata()
        metadata[quarantine_filename] = {
            'original_path': filepath,
            'original_filename': filename,
            'quarantine_date': quarantine_time,
            'file_hash': file_hash,
            'file_size': file_size,
            'reason': 'Suspicious extension'
        }
        save_quarantine_metadata(metadata)
        
        logging.info(f"Quarantined file: {filepath} -> {quarantine_path}")
        return True
        
    except Exception as e:
        logging.error(f"Error quarantining file {filepath}: {e}")
        return False

def delete_file(filepath):
    """Permanently deletes a file."""
    try:
        os.remove(filepath)
        logging.warning(f"PERMANENTLY DELETED file: {filepath}")
        return True
    except Exception as e:
        logging.error(f"Error deleting file {filepath}: {e}")
        return False

def scan_directory(directory, progress_bar, result_text_widget):
    """
    Recursively scans a directory and analyzes files.
    This simulates 'File Scanner', 'Signature Detection' (as hash checking),
    and 'Heuristic Analysis' (as extension checking).
    """
    logging.info(f"--- Starting scan on directory: {directory} ---")
    result_text_widget.insert(tk.END, f"--- Starting scan on: {directory} ---\n")
    
    suspicious_files = []
    file_hashes = {}
    total_files = 0
    scanned_files = 0

    # First pass: count total files for the progress bar
    for root, _, files in os.walk(directory, topdown=True):
        total_files += len(files)
    
    if total_files > 0:
        progress_bar['maximum'] = total_files
    else:
        progress_bar['maximum'] = 1 # Avoid division by zero
        progress_bar['value'] = 1

    # Second pass: scan files
    for root, _, files in os.walk(directory, topdown=True):
        for filename in files:
            filepath = os.path.join(root, filename)
            
            # Update progress
            scanned_files += 1
            progress_bar['value'] = scanned_files
            progress_bar.update_idletasks() # Force GUI update

            try:
                # 1. Heuristic Check: Suspicious Extension
                _, ext = os.path.splitext(filename)
                if ext.lower() in SUSPICIOUS_EXTENSIONS:
                    log_msg = f"[SUSPICIOUS] File with potentially harmful extension found: {filepath}"
                    logging.warning(log_msg)
                    suspicious_files.append(filepath)
                    result_text_widget.insert(tk.END, f"{log_msg}\n", 'warning')

                # 2. Signature Check (Simulation): Hashing
                # A real AV would compare this hash to a database of malware.
                # We will just log the hash.
                file_hash = get_file_hash(filepath)
                
                if file_hash:
                    # Check for duplicates (another simple heuristic)
                    if file_hash in file_hashes:
                        log_msg = f"[INFO] Duplicate file detected (same hash): {filepath} is a copy of {file_hashes[file_hash]}"
                        logging.info(log_msg)
                        result_text_widget.insert(tk.END, f"{log_msg}\n", 'info')
                    else:
                        file_hashes[file_hash] = filepath
                        
            except Exception as e:
                logging.error(f"Error processing file {filepath}: {e}")
                result_text_widget.insert(tk.END, f"[ERROR] Could not process {filepath}: {e}\n", 'error')

    # 3. Logging and Reporting
    log_msg = f"--- Scan Complete ---"
    logging.info(log_msg)
    result_text_widget.insert(tk.END, f"\n{log_msg}\n", 'complete')
    
    summary_msg = f"Summary: Scanned {scanned_files} files. Found {len(suspicious_files)} files with suspicious extensions."
    logging.info(summary_msg)
    result_text_widget.insert(tk.END, f"{summary_msg}\n", 'complete')
    
    return suspicious_files

# --- GUI Class ---

class AntivirusSimulatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RealAntivirus")
        self.root.geometry("1000x720")
        self.root.minsize(500, 400)
        
        # Store current suspicious files
        self.current_suspicious_files = []
        
        # --- Configure Styles ---
        self.style = ttk.Style()
        self.style.theme_use('clam') # Use a clean theme

        # --- Global palette (themeable) ---
        # Store both palettes to support live switching
        self.colors_dark = {
            'bg_base': '#0b1220',
            'bg_panel': '#0f172a',
            'fg_text': '#e5e7eb',
            'fg_muted': '#9ca3af',
            'brand_primary': '#00A88E',
            'color_primary': '#2563eb',
            'color_primary_active': '#1d4ed8',
            'color_neutral': '#64748b',
            'color_neutral_active': '#4b5563',
            'color_accent': '#7c3aed',
            'color_accent_active': '#6d28d9',
            'color_critical': '#ef4444',
            'color_critical_active': '#dc2626',
            'trough': '#1f2937',
        }
        self.colors_light = {
            'bg_base': '#ffffff',
            'bg_panel': '#f8fafc',
            'fg_text': '#111827',
            'fg_muted': '#6b7280',
            'brand_primary': '#00A88E',
            'color_primary': '#2563eb',
            'color_primary_active': '#1d4ed8',
            'color_neutral': '#6b7280',
            'color_neutral_active': '#4b5563',
            'color_accent': '#7c3aed',
            'color_accent_active': '#6d28d9',
            'color_critical': '#ef4444',
            'color_critical_active': '#dc2626',
            'trough': '#e5e7eb',
        }

        # Buttons
        color_primary = '#2563eb'   # blue
        color_primary_active = '#1d4ed8'
        color_neutral = '#64748b'   # slate
        color_neutral_active = '#4b5563'
        color_accent = '#7c3aed'    # indigo/violet
        color_accent_active = '#6d28d9'
        color_critical = '#ef4444'  # red
        color_critical_active = '#dc2626'

        # Apply initial theme (dark by default)
        self.var_dark_theme = tk.BooleanVar(value=True)
        self.apply_theme(self.var_dark_theme.get())

        # Remove blue focus line by redefining layouts without the 'Button.focus' element
        button_no_focus_layout = [
            ('Button.border', {
                'sticky': 'nswe',
                'children': [
                    ('Button.padding', {
                        'sticky': 'nswe',
                        'children': [
                            ('Button.label', {'sticky': 'nswe'})
                        ]
                    })
                ]
            })
        ]
        for style_name in ('Primary.TButton', 'Neutral.TButton', 'Accent.TButton', 'Critical.TButton'):
            try:
                self.style.layout(style_name, button_no_focus_layout)
            except Exception:
                pass
        # Notebook/Progressbar/Treeview/Status styles are configured in apply_theme

        # --- Main Layout (Sidebar + Content) ---
        # Root bg is configured in apply_theme
        self.main_frame = ttk.Frame(root, padding="0 0 0 0")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        # rows: 0 topbar, 1 content, 2 status
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        # Top bar
        self.topbar = ttk.Frame(self.main_frame)
        self.topbar.grid(row=0, column=0, columnspan=2, sticky='ew')
        tb_title = ttk.Label(self.topbar, text="RealAntivirus", font=('Helvetica', 14, 'bold'))
        tb_title.pack(side=tk.LEFT, padx=12, pady=8)
        self.tb_status = ttk.Label(self.topbar, text="Definitions: Up to date", foreground='#22c55e')
        self.tb_status.pack(side=tk.LEFT, padx=8)
        # Dark/Light toggle button
        self.btn_theme_toggle = ttk.Button(self.topbar, text='🌙 Dark', style='Neutral.TButton', takefocus=False, command=self.toggle_dark_light)
        self.btn_theme_toggle.pack(side=tk.RIGHT, padx=6)
        ttk.Button(self.topbar, text="Check Updates", style='Neutral.TButton', command=lambda: messagebox.showinfo('Updates', 'Definitions are up to date.'), takefocus=False).pack(side=tk.RIGHT, padx=12)
        # Separator under topbar
        ttk.Separator(self.main_frame, orient='horizontal').grid(row=0, column=0, columnspan=2, sticky='ew', pady=(44,0))

        # Helper for current palette
        c = self.colors_dark if self.var_dark_theme.get() else self.colors_light

        # Sidebar
        self.sidebar = ttk.Frame(self.main_frame)
        self.sidebar.grid(row=1, column=0, sticky="nsw")
        # Sidebar header (logo/title)
        sb_header = ttk.Frame(self.sidebar)
        sb_header.pack(fill=tk.X, pady=(12, 12), padx=12)
        sb_title = ttk.Label(sb_header, text="🛡️ RealAntivirus", font=('Helvetica', 14, 'bold'))
        sb_title.pack(anchor=tk.W)
        sb_sub = ttk.Label(sb_header, text="Protected", foreground='#22c55e', font=('Helvetica', 10, 'bold'))
        sb_sub.pack(anchor=tk.W)

        # Sidebar nav buttons
        self.nav_buttons = {}
        def add_nav(name, text, command):
            btn = ttk.Button(self.sidebar, text=text, style='Neutral.TButton', command=command, takefocus=False)
            btn.pack(fill=tk.X, padx=12, pady=4)
            self.nav_buttons[name] = btn
        add_nav('dashboard', '🏠 Dashboard', lambda: self.show_view('dashboard'))
        add_nav('scan', '🧭 Scan', lambda: self.show_view('scan'))
        add_nav('quarantine', '📦 Quarantine', lambda: self.show_view('quarantine'))
        add_nav('reports', '📊 Reports', lambda: self.show_view('reports'))
        add_nav('settings', '⚙️ Settings', lambda: self.show_view('settings'))

        # Content area
        self.content = ttk.Frame(self.main_frame, padding="16 16 16 16")
        self.content.grid(row=1, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        # Views container (stacked frames)
        self.view_dashboard = ttk.Frame(self.content)
        self.view_scan = ttk.Frame(self.content)
        self.view_quarantine = ttk.Frame(self.content)
        self.view_reports = ttk.Frame(self.content)
        self.view_settings = ttk.Frame(self.content)
        for view in (self.view_dashboard, self.view_scan, self.view_quarantine, self.view_reports, self.view_settings):
            view.grid(row=0, column=0, sticky='nsew')

        # --- Dashboard View ---
        self.view_dashboard.grid_rowconfigure(2, weight=1)
        self.view_dashboard.grid_columnconfigure(0, weight=1)
        # Status card (with subtle border)
        status_card = ttk.Frame(self.view_dashboard, padding="12 12 12 12")
        status_card.grid(row=0, column=0, sticky='ew', pady=(0, 12))
        status_title = ttk.Label(status_card, text="System status: Protected", font=('Helvetica', 16, 'bold'), foreground='#22c55e')
        status_title.pack(anchor=tk.W)
        # Status badge
        status_badge = tk.Label(status_card, text='PROTECTED', bg='#22c55e', fg='#ffffff', padx=8, pady=2, font=('Helvetica', 9, 'bold'))
        status_badge.pack(anchor=tk.W, pady=(6, 2))
        status_desc = ttk.Label(status_card, text="No active threats detected. Definitions up to date.", foreground=c['fg_muted'])
        status_desc.pack(anchor=tk.W, pady=(4,0))
        # Quick actions
        qa = ttk.Frame(self.view_dashboard, padding="8 8 8 8")
        qa.grid(row=1, column=0, sticky='ew', pady=(0, 12))
        qa.grid_columnconfigure(0, weight=1)
        qa.grid_columnconfigure(1, weight=1)
        qa.grid_columnconfigure(2, weight=1)
        self.btn_quick_scan = ttk.Button(qa, text="⚡ Quick Scan", style='Primary.TButton', command=self.start_scan, takefocus=False)
        self.btn_quick_scan.grid(row=0, column=0, sticky='ew', padx=6)
        self.btn_full_scan = ttk.Button(qa, text="🖥️ Full Scan", style='Accent.TButton', command=self.start_scan, takefocus=False)
        self.btn_full_scan.grid(row=0, column=1, sticky='ew', padx=6)
        self.btn_update = ttk.Button(qa, text="⟳ Update Definitions", style='Neutral.TButton', command=lambda: messagebox.showinfo('Updates', 'Definitions are up to date.'), takefocus=False)
        self.btn_update.grid(row=0, column=2, sticky='ew', padx=6)
        # Recent activity (logs preview)
        dash_logs = scrolledtext.ScrolledText(self.view_dashboard, wrap=tk.WORD, height=12, font=("Consolas", 10))
        try:
            dash_logs.configure(bg=c['bg_base'], fg=c['fg_text'], insertbackground=c['fg_text'])
        except Exception:
            pass
        dash_logs.grid(row=2, column=0, sticky='nsew')
        self._dashboard_logs = dash_logs

        # --- Scan View ---
        self.view_scan.grid_rowconfigure(4, weight=1)
        self.view_scan.grid_columnconfigure(0, weight=1)
        # Header
        self.header_frame = ttk.Frame(self.view_scan)
        self.header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header = ttk.Label(self.header_frame, text="Scan for threats", font=('Helvetica', 16, 'bold'))
        header.pack(side=tk.LEFT)
        subtitle = ttk.Label(self.header_frame, text="Select a folder to scan or choose a mode", foreground=c['fg_muted'])
        subtitle.pack(side=tk.LEFT, padx=12)
        # Scan modes
        self.scan_mode = tk.StringVar(value='quick')
        modes = ttk.Frame(self.view_scan)
        modes.grid(row=1, column=0, sticky='ew', pady=(0, 8))
        ttk.Radiobutton(modes, text='⚡ Quick', value='quick', variable=self.scan_mode, takefocus=False).pack(side=tk.LEFT, padx=6)
        ttk.Radiobutton(modes, text='🖥️ Full', value='full', variable=self.scan_mode, takefocus=False).pack(side=tk.LEFT, padx=6)
        ttk.Radiobutton(modes, text='🗂️ Custom', value='custom', variable=self.scan_mode, takefocus=False).pack(side=tk.LEFT, padx=6)
        # Controls
        self.controls_frame = ttk.Frame(self.view_scan)
        self.controls_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        # Grid configuration for equal spacing
        self.controls_frame.grid_columnconfigure(0, weight=2)
        self.controls_frame.grid_columnconfigure(1, weight=1)
        self.controls_frame.grid_columnconfigure(2, weight=1)
        self.controls_frame.grid_columnconfigure(3, weight=1)

        self.scan_button = ttk.Button(self.controls_frame, text="Select Directory to Scan", command=self.start_scan, style='Primary.TButton', takefocus=False)
        self.scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.clear_button = ttk.Button(self.controls_frame, text="Clear Results", command=self.clear_results, style='Neutral.TButton', takefocus=False)
        self.clear_button.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        
        # Action buttons (initially disabled)
        self.quarantine_all_button = ttk.Button(self.controls_frame, text="Quarantine All", 
                                               command=self.quarantine_all, style='Accent.TButton', takefocus=False)
        self.quarantine_all_button.grid(row=0, column=2, sticky="ew", padx=(0, 8))
        self.quarantine_all_button.config(state=tk.DISABLED)
        
        self.delete_all_button = ttk.Button(self.controls_frame, text="Delete All", 
                                           command=self.delete_all, style='Critical.TButton', takefocus=False)
        self.delete_all_button.grid(row=0, column=3, sticky="ew")
        self.delete_all_button.config(state=tk.DISABLED)

        # --- Progress Bar ---
        self.progress = ttk.Progressbar(self.view_scan, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.grid(row=3, column=0, sticky="ew", pady=5)

        # --- Results Text Area ---
        self.result_text = scrolledtext.ScrolledText(self.view_scan, wrap=tk.WORD, height=10, font=("Consolas", 10))
        # Dark text area styling
        try:
            self.result_text.configure(bg=c['bg_base'], fg=c['fg_text'], insertbackground=c['fg_text'])
        except Exception:
            pass
        self.result_text.grid(row=4, column=0, sticky="nsew", pady=(5, 0))
        
        # Define text styles for logging
        self.result_text.tag_config('info', foreground='#2563eb')          # blue
        self.result_text.tag_config('warning', foreground='#b45309', font=('Consolas', 10, 'bold'))
        self.result_text.tag_config('error', foreground='#b91c1c')         # red
        self.result_text.tag_config('complete', foreground='#166534', font=('Consolas', 10, 'bold'))
		
        # --- Status Bar ---
        self.status_bar = ttk.Label(self.main_frame, text=f"Ready | Log file: {LOG_FILE}", relief=tk.SUNKEN, anchor=tk.W, style='Status.TLabel')
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        # --- Quarantine View ---
        self.view_quarantine.grid_rowconfigure(1, weight=1)
        self.view_quarantine.grid_columnconfigure(0, weight=1)
        q_controls = ttk.Frame(self.view_quarantine, padding="8 8 8 8")
        q_controls.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.refresh_quarantine_btn = ttk.Button(q_controls, text="Refresh", command=self.load_quarantine_table, takefocus=False)
        self.refresh_quarantine_btn.pack(side=tk.LEFT)
        ttk.Button(q_controls, text="Restore Selected", style='Primary.TButton', command=self.restore_selected_quarantine, takefocus=False).pack(side=tk.LEFT, padx=6)
        ttk.Button(q_controls, text="Delete Selected", style='Critical.TButton', command=self.delete_selected_quarantine, takefocus=False).pack(side=tk.LEFT)
        columns = ("original_filename", "original_path", "quarantine_date", "file_size", "file_hash", "reason")
        self.quarantine_tree = ttk.Treeview(self.view_quarantine, columns=columns, show='headings')
        self.quarantine_tree.grid(row=1, column=0, sticky="nsew")
        self.quarantine_tree.heading("original_filename", text="File")
        self.quarantine_tree.heading("original_path", text="Original Path")
        self.quarantine_tree.heading("quarantine_date", text="Quarantined At")
        self.quarantine_tree.heading("file_size", text="Size (bytes)")
        self.quarantine_tree.heading("file_hash", text="SHA-256")
        self.quarantine_tree.heading("reason", text="Reason")
        self.quarantine_tree.column("original_filename", width=180, anchor=tk.W)
        self.quarantine_tree.column("original_path", width=320, anchor=tk.W)
        self.quarantine_tree.column("quarantine_date", width=150, anchor=tk.W)
        self.quarantine_tree.column("file_size", width=110, anchor=tk.E)
        self.quarantine_tree.column("file_hash", width=260, anchor=tk.W)
        self.quarantine_tree.column("reason", width=140, anchor=tk.W)
        q_scroll_y = ttk.Scrollbar(self.view_quarantine, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscroll=q_scroll_y.set)
        q_scroll_y.grid(row=1, column=1, sticky="ns")

        # --- Reports (Logs) View ---
        self.view_reports.grid_rowconfigure(1, weight=1)
        self.view_reports.grid_columnconfigure(0, weight=1)
        l_controls = ttk.Frame(self.view_reports, padding="8 8 8 8")
        l_controls.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.refresh_logs_btn = ttk.Button(l_controls, text="Refresh", command=self.refresh_logs_view, takefocus=False)
        self.refresh_logs_btn.pack(side=tk.LEFT)
        self.log_filter_var = tk.StringVar()
        ttk.Entry(l_controls, textvariable=self.log_filter_var, width=24).pack(side=tk.LEFT, padx=6)
        ttk.Button(l_controls, text="Filter", command=self.apply_log_filter, takefocus=False).pack(side=tk.LEFT)
        ttk.Button(l_controls, text="Export", style='Neutral.TButton', command=self.export_logs, takefocus=False).pack(side=tk.RIGHT)
        self.logs_view = scrolledtext.ScrolledText(self.view_reports, wrap=tk.WORD, height=10, font=("Consolas", 10))
        try:
            self.logs_view.configure(bg=c['bg_base'], fg=c['fg_text'], insertbackground=c['fg_text'])
        except Exception:
            pass
        self.logs_view.grid(row=1, column=0, sticky="nsew")

        # --- Settings View ---
        self.view_settings.grid_rowconfigure(1, weight=0)
        self.view_settings.grid_columnconfigure(0, weight=1)
        settings_header = ttk.Label(self.view_settings, text="Settings", font=('Helvetica', 16, 'bold'))
        settings_header.grid(row=0, column=0, sticky='w', pady=(0, 12))
        settings_panel = ttk.Frame(self.view_settings)
        settings_panel.grid(row=1, column=0, sticky='ew')
        self.var_notifications = tk.BooleanVar(value=True)
        self.var_auto_update = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_panel, text='Enable notifications', variable=self.var_notifications, takefocus=False).grid(row=0, column=0, sticky='w', pady=4)
        ttk.Checkbutton(settings_panel, text='Auto-update definitions', variable=self.var_auto_update, takefocus=False).grid(row=1, column=0, sticky='w', pady=4)
        ttk.Checkbutton(settings_panel, text='Use dark theme', variable=self.var_dark_theme, command=self.on_theme_toggle, takefocus=False).grid(row=2, column=0, sticky='w', pady=4)

        # --- Setup ---
        setup_logging()
        logging.info("Application started.")
        self.result_text.insert(tk.END, "Welcome to the File Integrity Scanner.\n", 'info')
        self.result_text.insert(tk.END, f"Suspicious extensions configured: {', '.join(SUSPICIOUS_EXTENSIONS)}\n\n")
        self.load_quarantine_table()
        self.refresh_logs_view()
        # Populate dashboard logs preview
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    self._dashboard_logs.insert(tk.END, f.read())
        except Exception:
            pass
        # Show default view
        self.show_view('dashboard')

    def show_view(self, name):
        views = {
            'dashboard': self.view_dashboard,
            'scan': self.view_scan,
            'quarantine': self.view_quarantine,
            'reports': self.view_reports,
            'settings': self.view_settings,
        }
        for v in views.values():
            v.grid_remove()
        if name in views:
            views[name].grid()
        # Update sidebar button styles (simple highlight)
        for key, btn in self.nav_buttons.items():
            if key == name:
                btn.configure(style='Primary.TButton')
            else:
                btn.configure(style='Neutral.TButton')

    def on_theme_toggle(self):
        self.apply_theme(self.var_dark_theme.get())
        # Update toggle button label
        self.btn_theme_toggle.configure(text=('🌙 Dark' if self.var_dark_theme.get() else '☀️ Light'))

    def toggle_dark_light(self):
        self.var_dark_theme.set(not self.var_dark_theme.get())
        self.on_theme_toggle()

    def apply_theme(self, dark):
        c = self.colors_dark if dark else self.colors_light
        # Base styles
        self.style.configure('TFrame', background=c['bg_panel'])
        self.style.configure('TLabel', background=c['bg_panel'], foreground=c['fg_text'], font=('Helvetica', 10))
        self.style.configure('TButton', padding=8, relief='flat', font=('Helvetica', 10, 'bold'))
        self.style.map('TButton', foreground=[('active', c['fg_text'])])
        # Buttons
        self.style.configure('Primary.TButton', background=c['brand_primary'], foreground='#ffffff')
        self.style.map('Primary.TButton', background=[('active', c['color_primary_active'])])
        self.style.configure('Neutral.TButton', background=c['color_neutral'], foreground='#ffffff')
        self.style.map('Neutral.TButton', background=[('active', c['color_neutral_active'])])
        self.style.configure('Accent.TButton', background=c['color_accent'], foreground='#ffffff')
        self.style.map('Accent.TButton', background=[('active', c['color_accent_active'])])
        self.style.configure('Critical.TButton', background=c['color_critical'], foreground='#ffffff')
        self.style.map('Critical.TButton', background=[('active', c['color_critical_active'])])
        # Progressbar
        self.style.configure('TProgressbar', thickness=18, background=c['brand_primary'], troughcolor=c['trough'])
        # Notebook / Treeview / Status
        self.style.configure('TNotebook', background=c['bg_panel'], borderwidth=0)
        self.style.configure('TNotebook.Tab', background=c['trough'], foreground=c['fg_muted'], padding=(14, 8))
        self.style.map('TNotebook.Tab', background=[('selected', c['color_primary'])], foreground=[('selected', '#ffffff')])
        self.style.configure('Treeview', rowheight=26, background=c['bg_panel'], fieldbackground=c['bg_panel'], foreground=c['fg_text'], bordercolor='#374151')
        self.style.map('Treeview', background=[('selected', c['color_primary'])], foreground=[('selected', '#ffffff')])
        self.style.configure('Treeview.Heading', font=('Helvetica', 10, 'bold'), background=c['trough'], foreground=c['fg_text'])
        self.style.configure('Status.TLabel', background=(c['bg_base'] if dark else '#eef2ff'), foreground=c['fg_text'])
        # Root/window bg
        try:
            self.root.configure(bg=c['bg_base'])
        except Exception:
            pass
        # Text widgets
        for w in getattr(self, 'result_text', []), getattr(self, 'logs_view', []), getattr(self, '_dashboard_logs', []):
            try:
                w.configure(bg=c['bg_base'], fg=c['fg_text'], insertbackground=c['fg_text'])
            except Exception:
                pass

    def apply_log_filter(self):
        query = (self.log_filter_var.get() or '').strip().lower()
        self.refresh_logs_view()
        if not query:
            return
        content = self.logs_view.get('1.0', tk.END)
        lines = [ln for ln in content.splitlines() if query in ln.lower()]
        self.logs_view.delete('1.0', tk.END)
        self.logs_view.insert(tk.END, '\n'.join(lines))

    def export_logs(self):
        try:
            if not os.path.exists(LOG_FILE):
                messagebox.showinfo('Export Logs', 'No log file to export yet.')
                return
            dest = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text Files', '*.txt')], title='Export Logs')
            if not dest:
                return
            with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as src, open(dest, 'w', encoding='utf-8') as out:
                out.write(src.read())
            messagebox.showinfo('Export Logs', f'Logs exported to\n{dest}')
        except Exception as e:
            messagebox.showerror('Export Logs', f'Failed to export: {e}')

    def restore_selected_quarantine(self):
        sel = self.quarantine_tree.selection()
        if not sel:
            messagebox.showinfo('Quarantine', 'No items selected.')
            return
        metadata = load_quarantine_metadata()
        restored = 0
        failed = 0
        for qname in sel:
            try:
                info = None
                if qname in metadata:
                    info = metadata[qname]
                else:
                    # Fallback: search by matching row values
                    info = None
                if not info:
                    failed += 1
                    continue
                quarantine_path = os.path.join(QUARANTINE_FOLDER, qname)
                original_path = info.get('original_path')
                if not original_path:
                    failed += 1
                    continue
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                if os.path.exists(quarantine_path):
                    shutil.move(quarantine_path, original_path)
                    restored += 1
                    # remove from metadata
                    metadata.pop(qname, None)
                else:
                    failed += 1
            except Exception:
                failed += 1
        save_quarantine_metadata(metadata)
        self.load_quarantine_table()
        messagebox.showinfo('Quarantine', f'Restored: {restored}\nFailed: {failed}')

    def delete_selected_quarantine(self):
        sel = self.quarantine_tree.selection()
        if not sel:
            messagebox.showinfo('Quarantine', 'No items selected.')
            return
        if not messagebox.askyesno('Confirm', 'Permanently delete selected quarantined files?'):
            return
        metadata = load_quarantine_metadata()
        deleted = 0
        failed = 0
        for qname in sel:
            try:
                quarantine_path = os.path.join(QUARANTINE_FOLDER, qname)
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                    deleted += 1
                metadata.pop(qname, None)
            except Exception:
                failed += 1
        save_quarantine_metadata(metadata)
        self.load_quarantine_table()
        messagebox.showinfo('Quarantine', f'Deleted: {deleted}\nFailed: {failed}')

    def start_scan(self):
        """Asks user for a directory and starts the scan logic."""
        directory = filedialog.askdirectory()
        if not directory:
            messagebox.showinfo("Scan Cancelled", "No directory selected.")
            return
            
        # Clear previous results
        self.clear_results(log_msg=False)
        self.status_bar.config(text=f"Scanning... {directory}")
        self.progress['value'] = 0
        self.scan_button.config(state=tk.DISABLED)
        
        # Run the scan
        # We use a simple update loop instead of threading for simplicity
        # For large scans, threading would be required to prevent GUI lockup
        try:
            suspicious_files = scan_directory(directory, self.progress, self.result_text)
            self.current_suspicious_files = suspicious_files
            self.status_bar.config(text=f"Scan complete. Found {len(suspicious_files)} suspicious files.")
            
            # Enable action buttons if suspicious files were found
            if suspicious_files:
                self.quarantine_all_button.config(state=tk.NORMAL)
                self.delete_all_button.config(state=tk.NORMAL)
                messagebox.showinfo("Scan Complete", 
                                  f"Scan finished.\n\nFound {len(suspicious_files)} files with suspicious extensions.\n\n"
                                  "Use 'Quarantine All' or 'Delete All' to handle them.")
            else:
                self.quarantine_all_button.config(state=tk.DISABLED)
                self.delete_all_button.config(state=tk.DISABLED)
                messagebox.showinfo("Scan Complete", "No suspicious files found. Your system appears clean.")
        except Exception as e:
            logging.error(f"An unexpected error occurred during scan: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")
            self.status_bar.config(text="Scan failed with error.")
            
        self.scan_button.config(state=tk.NORMAL)

    def quarantine_all(self):
        """Quarantines all suspicious files."""
        if not self.current_suspicious_files:
            messagebox.showwarning("No Files", "No suspicious files to quarantine.")
            return
        
        # Confirm action
        response = messagebox.askyesno(
            "Confirm Quarantine",
            f"Are you sure you want to QUARANTINE {len(self.current_suspicious_files)} file(s)?\n\n"
            f"Files will be moved to the '{QUARANTINE_FOLDER}' folder.\n"
            "This action is reversible."
        )
        
        if not response:
            return
        
        quarantined_count = 0
        failed_count = 0
        
        for filepath in self.current_suspicious_files:
            if os.path.exists(filepath):
                if quarantine_file(filepath, len(self.current_suspicious_files)):
                    quarantined_count += 1
                    self.result_text.insert(tk.END, f"[QUARANTINED] {filepath}\n", 'complete')
                else:
                    failed_count += 1
                    self.result_text.insert(tk.END, f"[FAILED] Could not quarantine: {filepath}\n", 'error')
            else:
                failed_count += 1
                self.result_text.insert(tk.END, f"[FAILED] File not found: {filepath}\n", 'error')
        
        self.result_text.insert(tk.END, f"\n[COMPLETE] Quarantined: {quarantined_count}, Failed: {failed_count}\n", 'complete')
        self.status_bar.config(text=f"Quarantine complete. {quarantined_count} files quarantined, {failed_count} failed.")
        
        # Disable buttons after action
        self.quarantine_all_button.config(state=tk.DISABLED)
        self.delete_all_button.config(state=tk.DISABLED)
        self.current_suspicious_files = []
        
        messagebox.showinfo("Quarantine Complete", 
                          f"Quarantine finished.\n\n"
                          f"Successfully quarantined: {quarantined_count} files\n"
                          f"Failed: {failed_count} files")

    def delete_all(self):
        """Deletes all suspicious files permanently."""
        if not self.current_suspicious_files:
            messagebox.showwarning("No Files", "No suspicious files to delete.")
            return
        
        # Confirm action - with strong warning
        response = messagebox.askyesno(
            "⚠️ CONFIRM PERMANENT DELETION ⚠️",
            f"WARNING: This will PERMANENTLY DELETE {len(self.current_suspicious_files)} file(s)!\n\n"
            f"This action CANNOT be undone.\n\n"
            "Are you absolutely sure you want to proceed?",
            icon='warning'
        )
        
        if not response:
            return
        
        # Double confirmation
        response2 = messagebox.askyesno(
            "⚠️ FINAL CONFIRMATION ⚠️",
            "Last chance! These files will be PERMANENTLY DELETED.\n\n"
            "Are you sure?",
            icon='warning'
        )
        
        if not response2:
            return
        
        deleted_count = 0
        failed_count = 0
        
        for filepath in self.current_suspicious_files:
            if os.path.exists(filepath):
                if delete_file(filepath):
                    deleted_count += 1
                    self.result_text.insert(tk.END, f"[DELETED] {filepath}\n", 'error')
                else:
                    failed_count += 1
                    self.result_text.insert(tk.END, f"[FAILED] Could not delete: {filepath}\n", 'error')
            else:
                failed_count += 1
                self.result_text.insert(tk.END, f"[FAILED] File not found: {filepath}\n", 'error')
        
        self.result_text.insert(tk.END, f"\n[COMPLETE] Deleted: {deleted_count}, Failed: {failed_count}\n", 'complete')
        self.status_bar.config(text=f"Deletion complete. {deleted_count} files deleted, {failed_count} failed.")
        
        # Disable buttons after action
        self.quarantine_all_button.config(state=tk.DISABLED)
        self.delete_all_button.config(state=tk.DISABLED)
        self.current_suspicious_files = []
        
        messagebox.showinfo("Deletion Complete", 
                          f"Deletion finished.\n\n"
                          f"Successfully deleted: {deleted_count} files\n"
                          f"Failed: {failed_count} files")

    def clear_results(self, log_msg=True):
        """Clears the result text widget."""
        self.result_text.delete('1.0', tk.END)
        self.progress['value'] = 0
        self.quarantine_all_button.config(state=tk.DISABLED)
        self.delete_all_button.config(state=tk.DISABLED)
        self.current_suspicious_files = []
        if log_msg:
            logging.info("Results cleared by user.")
            self.result_text.insert(tk.END, "Results cleared.\n", 'info')
        self.status_bar.config(text="Ready")

    def load_quarantine_table(self):
        """Loads quarantine metadata into the Treeview (read-only viewer)."""
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        metadata = load_quarantine_metadata()
        for qname, info in metadata.items():
            # store qname as item iid so we can operate on selections
            self.quarantine_tree.insert('', tk.END, iid=qname, values=(
                info.get('original_filename', ''),
                info.get('original_path', ''),
                info.get('quarantine_date', ''),
                info.get('file_size', ''),
                info.get('file_hash', ''),
                info.get('reason', '')
            ))

    def refresh_logs_view(self):
        """Refreshes the Logs tab content from the log file."""
        self.logs_view.delete('1.0', tk.END)
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    self.logs_view.insert(tk.END, f.read())
            else:
                self.logs_view.insert(tk.END, "Log file not found. It will be created after the first run.")
        except Exception as e:
            self.logs_view.insert(tk.END, f"Failed to read log file: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = AntivirusSimulatorApp(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Failed to start the application: {e}")
        # Fallback for critical startup errors
        print(f"CRITICAL: Failed to start GUI. Error: {e}")

