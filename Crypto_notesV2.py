#!/usr/bin/env python3
"""
Stealth Encrypted Notes Application
A secure, stealthy note-taking app that runs in system tray with hotkey access.
Enhanced with security hardening and minimal visual footprint.
"""

import os
import json
import hashlib
import base64
import sys
import tempfile
import shutil
import threading
import time
import stat
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from uuid import uuid4
from typing import Dict, Any, Optional
import subprocess

# Platform-specific imports
if sys.platform.startswith('win'):
    try:
        import winreg
    except ImportError:
        winreg = None

# GUI imports
try:
    from PySide6.QtWidgets import (QApplication, QSystemTrayIcon, QMenu, QDialog,
                                   QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
                                   QLabel, QTextEdit, QListWidget, QMessageBox,
                                   QInputDialog, QCheckBox, QSpinBox, QWidget,
                                   QListWidgetItem)
    from PySide6.QtCore import QTimer, Qt, QThread, Signal, QSettings, QStandardPaths
    from PySide6.QtGui import QIcon, QPixmap, QKeySequence, QShortcut, QAction, QPainter, QBrush

    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("Warning: GUI components not available. Install PySide6 for stealth mode.")


class SecurityManager:
    """Enhanced security features for the stealth app"""

    @staticmethod
    def set_file_permissions(filepath: str):
        """Set restrictive file permissions (Windows ACLs)"""
        try:
            if sys.platform.startswith('win'):
                # Remove inheritance and set owner-only permissions
                username = os.getenv("USERNAME")
                if username:
                    subprocess.run([
                        'icacls', filepath, '/inheritance:r', '/grant:r',
                        f'{username}:F'
                    ], capture_output=True, check=False)
            else:
                # Unix-like systems
                os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass  # Fail silently to avoid detection

    @staticmethod
    def secure_delete(filepath: str):
        """Securely delete file by overwriting"""
        try:
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                with open(filepath, 'r+b') as f:
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                os.remove(filepath)
        except Exception:
            pass

    @staticmethod
    def clear_clipboard():
        """Clear system clipboard"""
        try:
            if GUI_AVAILABLE:
                clipboard = QApplication.clipboard()
                clipboard.clear()
        except Exception:
            pass


class AutoLockManager:
    """Handles automatic locking after inactivity"""

    def __init__(self, app_instance, timeout_minutes=5):
        self.app = app_instance
        self.timeout_minutes = timeout_minutes
        self.timer = None
        self.enabled = True

    def reset_timer(self):
        """Reset the inactivity timer"""
        if self.timer:
            self.timer.stop()
        if self.enabled and self.app.authenticated and GUI_AVAILABLE:
            self.timer = QTimer()
            self.timer.timeout.connect(self.auto_lock)
            self.timer.start(self.timeout_minutes * 60 * 1000)

    def auto_lock(self):
        """Lock the application automatically"""
        if self.app.authenticated:
            self.app.logout()
            if hasattr(self.app, 'gui_instance') and self.app.gui_instance and hasattr(self.app.gui_instance,
                                                                                       'tray_icon'):
                self.app.gui_instance.tray_icon.showMessage(
                    "Auto-locked",
                    "Session locked due to inactivity",
                    QSystemTrayIcon.MessageIcon.Information,
                    2000
                )


class ClipboardManager:
    """Manages clipboard security"""

    def __init__(self):
        self.clear_timer = None

    def copy_with_timeout(self, text: str, timeout_seconds=30):
        """Copy text to clipboard and clear after timeout"""
        if GUI_AVAILABLE:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)

            # Clear after timeout
            if self.clear_timer:
                self.clear_timer.stop()
            self.clear_timer = QTimer()
            self.clear_timer.timeout.connect(SecurityManager.clear_clipboard)
            self.clear_timer.start(timeout_seconds * 1000)


class StealthEncryptedNotesApp:
    """Enhanced stealth version of the encrypted notes app"""

    def __init__(self):
        self.storage_dir = self._get_stealth_storage_directory()
        self.notes_file = os.path.join(self.storage_dir, ".enc_data.dat")
        self.password_file = os.path.join(self.storage_dir, ".auth_hash.dat")
        self.config_file = os.path.join(self.storage_dir, ".app_cfg.dat")

        # Create storage directory with restrictive permissions
        os.makedirs(self.storage_dir, exist_ok=True)
        SecurityManager.set_file_permissions(self.storage_dir)

        self.authenticated = False
        self.cipher_suite = None
        self.decrypted_notes_cache = {}

        # Security managers
        self.auto_lock_manager = None
        self.clipboard_manager = ClipboardManager()

        # GUI reference
        self.gui_instance = None

        # Settings
        self.settings = QSettings('StealthNotes', 'SecureNotes') if GUI_AVAILABLE else None

    def _get_stealth_storage_directory(self):
        """Get a less obvious storage directory"""
        if sys.platform.startswith('win'):
            # Use Local AppData with inconspicuous name
            local_data = Path(os.getenv('LOCALAPPDATA', Path.home() / 'AppData' / 'Local'))
            storage_path = local_data / 'Microsoft' / 'Windows' / 'Temp' / '.sysconfig'
        else:
            # Unix-like: hidden directory in user config
            storage_path = Path.home() / '.config' / '.sysdata'

        return str(storage_path)

    def _derive_key_from_password_scrypt(self, password, salt, n=16384, r=8, p=1, dklen=32):
        """Derive encryption key using scrypt"""
        key_raw = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
        return base64.urlsafe_b64encode(key_raw)

    def _hash_password_scrypt(self, password, *, n=16384, r=8, p=1, dklen=32):
        """Create secure scrypt hash record"""
        salt = os.urandom(16)
        pwdhash = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
        record = {
            'version': 2,
            'kdf': 'scrypt',
            'salt': base64.b64encode(salt).decode('ascii'),
            'n': n, 'r': r, 'p': p, 'dklen': dklen,
            'hash': base64.b64encode(pwdhash).decode('ascii'),
        }
        return record

    def _load_password_record(self):
        """Load password record securely"""
        if not os.path.exists(self.password_file):
            return None
        try:
            with open(self.password_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def _save_password_record(self, record):
        """Save password record securely"""
        data = json.dumps(record, ensure_ascii=False, indent=2)
        fd, tmp_path = tempfile.mkstemp(dir=self.storage_dir, prefix=".tmp-", suffix=".dat")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(data)
            os.replace(tmp_path, self.password_file)
            SecurityManager.set_file_permissions(self.password_file)
        finally:
            if os.path.exists(tmp_path):
                SecurityManager.secure_delete(tmp_path)

    def _verify_password(self, record, provided_password):
        """Verify password against record"""
        if not record or record.get('kdf') != 'scrypt':
            return False

        salt = base64.b64decode(record['salt'])
        n = int(record.get('n', 16384))
        r = int(record.get('r', 8))
        p = int(record.get('p', 1))
        dklen = int(record.get('dklen', 32))
        expected = base64.b64decode(record['hash'])
        computed = hashlib.scrypt(provided_password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
        return computed == expected

    def _load_config(self):
        """Load application config"""
        if not os.path.exists(self.config_file):
            return {}
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_config(self, config):
        """Save application config securely"""
        data = json.dumps(config, ensure_ascii=False, indent=2)
        fd, tmp_path = tempfile.mkstemp(dir=self.storage_dir, prefix=".tmp-", suffix=".dat")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(data)
            os.replace(tmp_path, self.config_file)
            SecurityManager.set_file_permissions(self.config_file)
        finally:
            if os.path.exists(tmp_path):
                SecurityManager.secure_delete(tmp_path)

    def setup_password(self, password):
        """Set up initial password"""
        if os.path.exists(self.password_file):
            return False

        if len(password) < 8:
            return False

        # Create password record
        record = self._hash_password_scrypt(password)
        self._save_password_record(record)

        # Initialize encryption config
        config = self._load_config()
        enc_salt = os.urandom(16)
        config['encryption'] = {
            'version': 1,
            'kdf': 'scrypt',
            'salt': base64.b64encode(enc_salt).decode('ascii'),
            'n': 16384, 'r': 8, 'p': 1, 'dklen': 32,
        }
        self._save_config(config)

        return True

    def authenticate(self, password):
        """Authenticate user"""
        record = self._load_password_record()
        if not self._verify_password(record, password):
            return False

        self.authenticated = True

        # Create cipher suite
        config = self._load_config()
        if 'encryption' in config:
            enc = config['encryption']
            enc_salt = base64.b64decode(enc['salt'])
            key = self._derive_key_from_password_scrypt(
                password, enc_salt,
                n=int(enc.get('n', 16384)),
                r=int(enc.get('r', 8)),
                p=int(enc.get('p', 1)),
                dklen=int(enc.get('dklen', 32)),
            )
            self.cipher_suite = Fernet(key)

        # Load and decrypt notes into memory
        self._load_decrypted_notes()

        # Start auto-lock timer
        if self.auto_lock_manager:
            self.auto_lock_manager.reset_timer()

        return True

    def logout(self):
        """Logout and clear sensitive data"""
        self.authenticated = False
        self.cipher_suite = None

        # Clear decrypted notes from memory
        self.decrypted_notes_cache.clear()

        # Clear clipboard
        SecurityManager.clear_clipboard()

        # Stop auto-lock timer
        if self.auto_lock_manager and self.auto_lock_manager.timer:
            self.auto_lock_manager.timer.stop()

    def _load_decrypted_notes(self):
        """Load and decrypt all notes into memory"""
        if not self.authenticated:
            return

        encrypted_notes = self._load_encrypted_notes()
        self.decrypted_notes_cache.clear()

        for note_id, note_data in encrypted_notes.items():
            try:
                self.decrypted_notes_cache[note_id] = {
                    'title': self._decrypt_text(note_data['title']),
                    'content': self._decrypt_text(note_data['content']),
                    'created': note_data['created']
                }
            except Exception:
                pass  # Skip corrupted notes

    def _load_encrypted_notes(self):
        """Load encrypted notes from disk"""
        if not os.path.exists(self.notes_file):
            return {}
        try:
            with open(self.notes_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_encrypted_notes(self, notes):
        """Save encrypted notes to disk"""
        data = json.dumps(notes, ensure_ascii=False, indent=2)
        fd, tmp_path = tempfile.mkstemp(dir=self.storage_dir, prefix=".tmp-", suffix=".dat")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(data)
            os.replace(tmp_path, self.notes_file)
            SecurityManager.set_file_permissions(self.notes_file)
        finally:
            if os.path.exists(tmp_path):
                SecurityManager.secure_delete(tmp_path)

    def _encrypt_text(self, text):
        """Encrypt text"""
        if not self.authenticated or not self.cipher_suite:
            raise Exception("Not authenticated")
        return self.cipher_suite.encrypt(text.encode('utf-8')).decode('utf-8')

    def _decrypt_text(self, encrypted_text):
        """Decrypt text"""
        if not self.authenticated or not self.cipher_suite:
            raise Exception("Not authenticated")
        return self.cipher_suite.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')

    def add_note(self, title, content):
        """Add a new note (in-memory and encrypted on disk)"""
        if not self.authenticated:
            return False

        note_id = uuid4().hex
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Add to memory cache
        self.decrypted_notes_cache[note_id] = {
            'title': title,
            'content': content,
            'created': timestamp
        }

        # Save encrypted version to disk
        encrypted_notes = self._load_encrypted_notes()
        encrypted_notes[note_id] = {
            'title': self._encrypt_text(title),
            'content': self._encrypt_text(content),
            'created': timestamp
        }
        self._save_encrypted_notes(encrypted_notes)

        if self.auto_lock_manager:
            self.auto_lock_manager.reset_timer()

        return note_id

    def update_note(self, note_id, title, content):
        """Update an existing note"""
        if not self.authenticated or note_id not in self.decrypted_notes_cache:
            return False

        # Update memory cache
        self.decrypted_notes_cache[note_id]['title'] = title
        self.decrypted_notes_cache[note_id]['content'] = content

        # Update encrypted version on disk
        encrypted_notes = self._load_encrypted_notes()
        if note_id in encrypted_notes:
            encrypted_notes[note_id]['title'] = self._encrypt_text(title)
            encrypted_notes[note_id]['content'] = self._encrypt_text(content)
            self._save_encrypted_notes(encrypted_notes)

        if self.auto_lock_manager:
            self.auto_lock_manager.reset_timer()

        return True

    def delete_note(self, note_id):
        """Delete a note"""
        if not self.authenticated or note_id not in self.decrypted_notes_cache:
            return False

        # Remove from memory
        del self.decrypted_notes_cache[note_id]

        # Remove from disk
        encrypted_notes = self._load_encrypted_notes()
        if note_id in encrypted_notes:
            del encrypted_notes[note_id]
            self._save_encrypted_notes(encrypted_notes)

        if self.auto_lock_manager:
            self.auto_lock_manager.reset_timer()

        return True

    def get_notes(self):
        """Get all decrypted notes from memory"""
        if not self.authenticated:
            return {}
        return self.decrypted_notes_cache.copy()

    def copy_note_to_clipboard(self, note_id):
        """Copy note content to clipboard with timeout"""
        if not self.authenticated or note_id not in self.decrypted_notes_cache:
            return False

        note = self.decrypted_notes_cache[note_id]
        content = f"{note['title']}\n\n{note['content']}"
        self.clipboard_manager.copy_with_timeout(content, timeout_seconds=30)

        if self.auto_lock_manager:
            self.auto_lock_manager.reset_timer()

        return True


# GUI Components for Stealth Mode
class UnlockDialog(QDialog):
    """Minimal unlock dialog"""

    def __init__(self, app_instance):
        super().__init__()
        self.app_instance = app_instance
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("System Verification")
        self.setFixedSize(300, 120)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Tool)

        layout = QVBoxLayout()

        # Password field
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_field.setPlaceholderText("Enter verification code")
        self.password_field.returnPressed.connect(self.authenticate)

        # Buttons
        button_layout = QHBoxLayout()
        unlock_btn = QPushButton("Unlock")
        cancel_btn = QPushButton("Cancel")

        unlock_btn.clicked.connect(self.authenticate)
        cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(unlock_btn)
        button_layout.addWidget(cancel_btn)

        layout.addWidget(QLabel("System verification required:"))
        layout.addWidget(self.password_field)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Set focus to password field
        self.password_field.setFocus()

    def authenticate(self):
        password = self.password_field.text()
        if self.app_instance.authenticate(password):
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Invalid verification code")
            self.password_field.clear()
            self.password_field.setFocus()


class NotesWindow(QDialog):
    """Main notes window"""

    def __init__(self, app_instance):
        super().__init__()
        self.app_instance = app_instance
        self.note_ids = []  # List of note IDs corresponding to list items by index
        self.setup_ui()
        self.load_notes()

    def setup_ui(self):
        self.setWindowTitle("Secure Notes")
        self.setGeometry(200, 200, 600, 400)
        self.setWindowFlags(Qt.WindowType.Tool)

        layout = QVBoxLayout()

        # Notes list
        self.notes_list = QListWidget()
        self.notes_list.itemDoubleClicked.connect(self.edit_note)

        # Buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add")
        edit_btn = QPushButton("Edit")
        delete_btn = QPushButton("Delete")
        copy_btn = QPushButton("Copy")
        close_btn = QPushButton("Close")

        add_btn.clicked.connect(self.add_note)
        edit_btn.clicked.connect(self.edit_note)
        delete_btn.clicked.connect(self.delete_note)
        copy_btn.clicked.connect(self.copy_note)
        close_btn.clicked.connect(self.accept)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(edit_btn)
        btn_layout.addWidget(delete_btn)
        btn_layout.addWidget(copy_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)

        layout.addWidget(self.notes_list)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def load_notes(self):
        """Load notes into the list"""
        self.notes_list.clear()
        self.note_ids.clear()
        notes = self.app_instance.get_notes()

        for note_id, note_data in notes.items():
            title = note_data['title'][:50] + "..." if len(note_data['title']) > 50 else note_data['title']
            item_text = f"{title} ({note_data['created']})"
            item = QListWidgetItem(item_text)
            self.notes_list.addItem(item)
            # Store note_id in corresponding list position
            self.note_ids.append(note_id)

    def get_selected_note_id(self):
        """Get the note ID of the currently selected item"""
        current_row = self.notes_list.currentRow()
        if 0 <= current_row < len(self.note_ids):
            return self.note_ids[current_row]
        return None

    def add_note(self):
        """Add new note"""
        dialog = NoteEditDialog(self, "", "")
        if dialog.exec():
            title, content = dialog.get_content()
            if title.strip() or content.strip():  # Only add if there's content
                self.app_instance.add_note(title, content)
                self.load_notes()

    def edit_note(self):
        """Edit selected note"""
        note_id = self.get_selected_note_id()
        if not note_id:
            QMessageBox.information(self, "No Selection", "Please select a note to edit.")
            return

        notes = self.app_instance.get_notes()
        if note_id not in notes:
            QMessageBox.warning(self, "Error", "Selected note not found.")
            self.load_notes()  # Refresh the list
            return

        note = notes[note_id]
        dialog = NoteEditDialog(self, note['title'], note['content'])
        if dialog.exec():
            title, content = dialog.get_content()
            self.app_instance.update_note(note_id, title, content)
            self.load_notes()

    def delete_note(self):
        """Delete selected note"""
        note_id = self.get_selected_note_id()
        if not note_id:
            QMessageBox.information(self, "No Selection", "Please select a note to delete.")
            return

        reply = QMessageBox.question(self, "Confirm Delete",
                                     "Delete selected note?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            self.app_instance.delete_note(note_id)
            self.load_notes()

    def copy_note(self):
        """Copy selected note to clipboard"""
        note_id = self.get_selected_note_id()
        if not note_id:
            QMessageBox.information(self, "No Selection", "Please select a note to copy.")
            return

        if self.app_instance.copy_note_to_clipboard(note_id):
            QMessageBox.information(self, "Copied",
                                    "Note copied to clipboard\n(Will be cleared in 30 seconds)")


class NoteEditDialog(QDialog):
    """Dialog for editing notes"""

    def __init__(self, parent, title="", content=""):
        super().__init__(parent)
        self.setup_ui(title, content)

    def setup_ui(self, title, content):
        self.setWindowTitle("Edit Note")
        self.setGeometry(250, 250, 500, 400)

        layout = QVBoxLayout()

        # Title field
        self.title_field = QLineEdit(title)
        self.title_field.setPlaceholderText("Note title")

        # Content field
        self.content_field = QTextEdit(content)
        self.content_field.setPlaceholderText("Note content")

        # Buttons
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")

        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addWidget(QLabel("Title:"))
        layout.addWidget(self.title_field)
        layout.addWidget(QLabel("Content:"))
        layout.addWidget(self.content_field)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        # Set focus to title field if empty, otherwise content
        if not title:
            self.title_field.setFocus()
        else:
            self.content_field.setFocus()

    def get_content(self):
        """Get the edited content"""
        return self.title_field.text(), self.content_field.toPlainText()


class StealthNotesGUI:
    """Main GUI application for stealth mode"""

    def __init__(self):
        if not GUI_AVAILABLE:
            raise RuntimeError("GUI components not available")

        self.app = QApplication.instance() or QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)

        self.notes_app = StealthEncryptedNotesApp()
        self.notes_app.gui_instance = self  # Set reference for auto-lock notifications
        self.notes_app.auto_lock_manager = AutoLockManager(self.notes_app)

        self.tray_icon = None
        self.hotkey_sequence = "Ctrl+Shift+N"

        self.setup_tray()
        self.setup_hotkey()

    def create_icon(self):
        """Create a simple system tray icon"""
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pixmap)
        # Make it more visible - blue circle with white 'N'
        painter.setBrush(QBrush(Qt.GlobalColor.blue))
        painter.setPen(Qt.GlobalColor.blue)
        painter.drawEllipse(1, 1, 14, 14)

        painter.setPen(Qt.GlobalColor.white)
        painter.drawText(5, 11, "N")  # 'N' for Notes
        painter.end()

        return QIcon(pixmap)

    def setup_tray(self):
        """Setup system tray icon"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            QMessageBox.critical(None, "System Tray",
                                 "System tray is not available on this system.")
            sys.exit(1)

        # Create a simple icon
        icon = self.create_icon()

        self.tray_icon = QSystemTrayIcon(icon, self.app)

        # Create tray menu
        menu = QMenu()

        unlock_action = QAction("Quick Access", self.app)
        unlock_action.triggered.connect(self.show_unlock_dialog)

        settings_action = QAction("Settings", self.app)
        settings_action.triggered.connect(self.show_settings)

        quit_action = QAction("Exit", self.app)
        quit_action.triggered.connect(self.quit_app)

        menu.addAction(unlock_action)
        menu.addSeparator()
        menu.addAction(settings_action)
        menu.addAction(quit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self.tray_activated)
        self.tray_icon.show()

    def setup_hotkey(self):
        """Setup global hotkey (simplified - would need proper global hotkey library)"""
        # This is a placeholder - you'd need a library like 'keyboard' or 'pyhook'
        # for true global hotkeys
        pass

    def tray_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_unlock_dialog()

    def show_unlock_dialog(self):
        """Show unlock dialog"""
        if self.notes_app.authenticated:
            self.show_notes_window()
        else:
            if not os.path.exists(self.notes_app.password_file):
                self.show_setup_dialog()
            else:
                dialog = UnlockDialog(self.notes_app)
                if dialog.exec():
                    self.show_notes_window()

    def show_setup_dialog(self):
        """Show initial password setup"""
        password, ok = QInputDialog.getText(None, "Setup",
                                            "Set master password (min 8 chars):",
                                            QLineEdit.EchoMode.Password)
        if ok and len(password) >= 8:
            if self.notes_app.setup_password(password):
                QMessageBox.information(None, "Setup Complete",
                                        "Password set successfully!")
            else:
                QMessageBox.warning(None, "Setup Error",
                                    "Failed to set password!")

    def show_notes_window(self):
        """Show main notes window"""
        if self.notes_app.authenticated:
            window = NotesWindow(self.notes_app)
            window.exec()

    def show_settings(self):
        """Show settings dialog"""
        # Placeholder for settings
        QMessageBox.information(None, "Settings", "Settings dialog not implemented yet")

    def quit_app(self):
        """Quit the application"""
        if self.notes_app.authenticated:
            self.notes_app.logout()
        if self.tray_icon:
            self.tray_icon.hide()
        self.app.quit()

    def run(self):
        """Run the GUI application"""
        return self.app.exec()


def main():
    """Main entry point"""
    if GUI_AVAILABLE:
        try:
            gui = StealthNotesGUI()
            return gui.run()
        except Exception as e:
            print(f"GUI mode failed: {e}")
            return 1
    else:
        print("Stealth mode requires PySide6. Install with: pip install PySide6")
        return 1


if __name__ == "__main__":
    sys.exit(main())