#!/usr/bin/env python3
"""
Encrypted Notes Application
A secure note-taking app that stores notes in encrypted format
and requires password authentication to view decrypted content.
"""

import os
import json
import getpass
import hashlib
import base64
import sys
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptedNotesApp:
    def __init__(self, custom_directory=None):
        # Determine the best storage location for .exe compatibility
        self.storage_dir = self._get_storage_directory(custom_directory)
        self.notes_file = os.path.join(self.storage_dir, "encrypted_notes.json")
        self.password_file = os.path.join(self.storage_dir, "password_hash.txt")
        self.config_file = os.path.join(self.storage_dir, "app_config.json")

        # Create storage directory if it doesn't exist
        os.makedirs(self.storage_dir, exist_ok=True)

        self.authenticated = False
        self.cipher_suite = None

        print(f"Storage location: {self.storage_dir}")

    def _get_storage_directory(self, custom_directory=None):
        """Get the appropriate storage directory for the application"""
        if custom_directory and os.path.exists(custom_directory):
            return custom_directory

        # For .exe applications, use user's Documents folder or AppData
        if sys.platform.startswith('win'):
            # Windows: Use Documents/EncryptedNotes
            documents = Path.home() / "Documents" / "EncryptedNotes"
            return str(documents)
        elif sys.platform.startswith('darwin'):
            # macOS: Use ~/Documents/EncryptedNotes
            documents = Path.home() / "Documents" / "EncryptedNotes"
            return str(documents)
        else:
            # Linux/Unix: Use ~/.local/share/EncryptedNotes
            local_share = Path.home() / ".local" / "share" / "EncryptedNotes"
            return str(local_share)

    def get_storage_info(self):
        """Display storage information"""
        print(f"\n=== STORAGE INFORMATION ===")
        print(f"Storage Directory: {self.storage_dir}")
        print(f"Notes File: {self.notes_file}")
        print(f"Password File: {self.password_file}")
        print(f"Notes file exists: {os.path.exists(self.notes_file)}")
        print(f"Password file exists: {os.path.exists(self.password_file)}")

        if os.path.exists(self.notes_file):
            file_size = os.path.getsize(self.notes_file)
            print(f"Notes file size: {file_size} bytes")

        # Count notes
        notes = self.load_notes()
        print(f"Number of notes: {len(notes)}")

    def change_storage_location(self):
        """Allow user to change storage location"""
        print(f"\nCurrent storage location: {self.storage_dir}")
        new_location = input("Enter new storage directory path (or press Enter to keep current): ").strip()

        if not new_location:
            print("Storage location unchanged.")
            return

        if not os.path.exists(new_location):
            create = input(f"Directory '{new_location}' doesn't exist. Create it? (y/n): ")
            if create.lower() == 'y':
                try:
                    os.makedirs(new_location, exist_ok=True)
                except Exception as e:
                    print(f"Error creating directory: {e}")
                    return
            else:
                print("Storage location unchanged.")
                return

        # Ask if user wants to move existing files
        old_notes_file = self.notes_file
        old_password_file = self.password_file

        move_files = False
        if os.path.exists(old_notes_file) or os.path.exists(old_password_file):
            move = input("Move existing notes and password to new location? (y/n): ")
            move_files = move.lower() == 'y'

        # Update storage location
        self.storage_dir = new_location
        self.notes_file = os.path.join(self.storage_dir, "encrypted_notes.json")
        self.password_file = os.path.join(self.storage_dir, "password_hash.txt")
        self.config_file = os.path.join(self.storage_dir, "app_config.json")

        # Move files if requested
        if move_files:
            try:
                if os.path.exists(old_notes_file):
                    os.rename(old_notes_file, self.notes_file)
                    print("Notes file moved successfully.")

                if os.path.exists(old_password_file):
                    os.rename(old_password_file, self.password_file)
                    print("Password file moved successfully.")

                # Remove old directory if empty
                old_dir = os.path.dirname(old_notes_file)
                try:
                    os.rmdir(old_dir)
                    print("Old storage directory removed.")
                except OSError:
                    pass  # Directory not empty or other error

            except Exception as e:
                print(f"Error moving files: {e}")
                return

        print(f"Storage location changed to: {self.storage_dir}")

    def backup_notes(self):
        """Create a backup of encrypted notes"""
        if not os.path.exists(self.notes_file):
            print("No notes file found to backup.")
            return

        backup_dir = os.path.join(self.storage_dir, "backups")
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_notes = os.path.join(backup_dir, f"notes_backup_{timestamp}.json")
        backup_password = os.path.join(backup_dir, f"password_backup_{timestamp}.txt")

        try:
            # Copy notes file
            with open(self.notes_file, 'r') as src, open(backup_notes, 'w') as dst:
                dst.write(src.read())

            # Copy password file
            if os.path.exists(self.password_file):
                with open(self.password_file, 'rb') as src, open(backup_password, 'wb') as dst:
                    dst.write(src.read())

            print(f"Backup created successfully in: {backup_dir}")
            print(f"Notes backup: {backup_notes}")
            print(f"Password backup: {backup_password}")

        except Exception as e:
            print(f"Error creating backup: {e}")

    def export_notes(self):
        """Export decrypted notes to a text file"""
        if not self.authenticated:
            print("Authentication required to export notes!")
            return

        notes = self.load_notes()
        if not notes:
            print("No notes found to export.")
            return

        export_file = os.path.join(self.storage_dir, f"notes_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

        try:
            with open(export_file, 'w', encoding='utf-8') as f:
                f.write("EXPORTED NOTES - DECRYPTED\n")
                f.write("=" * 50 + "\n\n")

                for note_id, note_data in notes.items():
                    try:
                        decrypted_title = self.decrypt_text(note_data['title'])
                        decrypted_content = self.decrypt_text(note_data['content'])

                        f.write(f"Note ID: {note_id}\n")
                        f.write(f"Created: {note_data['created']}\n")
                        f.write(f"Title: {decrypted_title}\n")
                        f.write(f"Content:\n{decrypted_content}\n")
                        f.write("-" * 50 + "\n\n")

                    except Exception as e:
                        f.write(f"Error decrypting note {note_id}: {e}\n\n")

            print(f"Notes exported successfully to: {export_file}")
            print("WARNING: This file contains unencrypted notes. Handle with care!")

        except Exception as e:
            print(f"Error exporting notes: {e}")

    def _derive_key_from_password(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key

    def _hash_password(self, password, salt=None):
        """Create a secure hash of the password"""
        if salt is None:
            salt = os.urandom(32)

        pwdhash = hashlib.pbkdf2_hmac('sha256',
                                      password.encode('utf-8'),
                                      salt,
                                      100000)
        return salt + pwdhash

    def _verify_password(self, stored_password, provided_password):
        """Verify a stored password against provided password"""
        salt = stored_password[:32]
        stored_hash = stored_password[32:]
        pwdhash = hashlib.pbkdf2_hmac('sha256',
                                      provided_password.encode('utf-8'),
                                      salt,
                                      100000)
        return pwdhash == stored_hash

    def setup_password(self):
        """Set up initial password for the application"""
        if os.path.exists(self.password_file):
            print("Password already exists!")
            return False

        print("Setting up your secure notes application...")
        password = getpass.getpass("Create a master password: ")
        confirm_password = getpass.getpass("Confirm password: ")

        if password != confirm_password:
            print("Passwords don't match!")
            return False

        if len(password) < 8:
            print("Password must be at least 8 characters long!")
            return False

        # Hash and store password
        hashed_password = self._hash_password(password)
        with open(self.password_file, 'wb') as f:
            f.write(hashed_password)

        print("Password set successfully!")
        return True

    def authenticate(self):
        """Authenticate user with password"""
        if not os.path.exists(self.password_file):
            print("No password set. Please run setup first.")
            if input("Would you like to set up a password now? (y/n): ").lower() == 'y':
                return self.setup_password()
            return False

        password = getpass.getpass("Enter your master password: ")

        with open(self.password_file, 'rb') as f:
            stored_password = f.read()

        if self._verify_password(stored_password, password):
            print("Authentication successful!")
            self.authenticated = True

            # Create cipher suite for encryption/decryption
            salt = stored_password[:32]  # Use the same salt from password
            key = self._derive_key_from_password(password, salt)
            self.cipher_suite = Fernet(key)

            return True
        else:
            print("Authentication failed!")
            return False

    def encrypt_text(self, text):
        """Encrypt text using the cipher suite"""
        if not self.authenticated or not self.cipher_suite:
            raise Exception("Not authenticated!")
        return self.cipher_suite.encrypt(text.encode('utf-8')).decode('utf-8')

    def decrypt_text(self, encrypted_text):
        """Decrypt text using the cipher suite"""
        if not self.authenticated or not self.cipher_suite:
            raise Exception("Not authenticated!")
        return self.cipher_suite.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')

    def load_notes(self):
        """Load notes from file"""
        if not os.path.exists(self.notes_file):
            return {}

        with open(self.notes_file, 'r') as f:
            return json.load(f)

    def save_notes(self, notes):
        """Save notes to file"""
        with open(self.notes_file, 'w') as f:
            json.dump(notes, f, indent=2)

    def view_encrypted_notes(self):
        """View notes in encrypted format (without authentication)"""
        notes = self.load_notes()
        if not notes:
            print("No notes found.")
            return

        print("\n=== ENCRYPTED NOTES ===")
        for note_id, note_data in notes.items():
            print(f"\nNote ID: {note_id}")
            print(f"Created: {note_data['created']}")
            print(f"Title (encrypted): {note_data['title']}")
            print(f"Content (encrypted): {note_data['content'][:100]}..." if len(
                note_data['content']) > 100 else f"Content (encrypted): {note_data['content']}")

    def view_decrypted_notes(self):
        """View notes in decrypted format (requires authentication)"""
        if not self.authenticated:
            print("Authentication required to view decrypted notes!")
            return

        notes = self.load_notes()
        if not notes:
            print("No notes found.")
            return

        print("\n=== DECRYPTED NOTES ===")
        for note_id, note_data in notes.items():
            try:
                decrypted_title = self.decrypt_text(note_data['title'])
                decrypted_content = self.decrypt_text(note_data['content'])

                print(f"\nNote ID: {note_id}")
                print(f"Created: {note_data['created']}")
                print(f"Title: {decrypted_title}")
                print(f"Content: {decrypted_content}")
                print("-" * 50)
            except Exception as e:
                print(f"Error decrypting note {note_id}: {e}")

    def add_note(self):
        """Add a new encrypted note"""
        if not self.authenticated:
            print("Authentication required to add notes!")
            return

        title = input("Enter note title: ")
        print("Enter note content (press Enter twice to finish):")
        content_lines = []
        while True:
            line = input()
            if line == "" and len(content_lines) > 0 and content_lines[-1] == "":
                content_lines.pop()  # Remove the last empty line
                break
            content_lines.append(line)

        content = "\n".join(content_lines)

        # Encrypt title and content
        encrypted_title = self.encrypt_text(title)
        encrypted_content = self.encrypt_text(content)

        # Load existing notes
        notes = self.load_notes()

        # Create new note
        note_id = str(len(notes) + 1).zfill(3)
        notes[note_id] = {
            'title': encrypted_title,
            'content': encrypted_content,
            'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Save notes
        self.save_notes(notes)
        print(f"Note added successfully with ID: {note_id}")

    def delete_note(self):
        """Delete a note"""
        if not self.authenticated:
            print("Authentication required to delete notes!")
            return

        notes = self.load_notes()
        if not notes:
            print("No notes found.")
            return

        self.view_decrypted_notes()
        note_id = input("\nEnter the Note ID to delete: ")

        if note_id in notes:
            confirm = input(f"Are you sure you want to delete note {note_id}? (y/n): ")
            if confirm.lower() == 'y':
                del notes[note_id]
                self.save_notes(notes)
                print("Note deleted successfully!")
            else:
                print("Deletion cancelled.")
        else:
            print("Note ID not found!")

    def change_password(self):
        """Change the master password"""
        if not self.authenticated:
            print("Authentication required to change password!")
            return

        # Load and decrypt all notes with current password
        notes = self.load_notes()
        decrypted_notes = {}

        for note_id, note_data in notes.items():
            try:
                decrypted_notes[note_id] = {
                    'title': self.decrypt_text(note_data['title']),
                    'content': self.decrypt_text(note_data['content']),
                    'created': note_data['created']
                }
            except Exception as e:
                print(f"Error decrypting note {note_id}: {e}")
                return

        # Get new password
        new_password = getpass.getpass("Enter new master password: ")
        confirm_password = getpass.getpass("Confirm new password: ")

        if new_password != confirm_password:
            print("Passwords don't match!")
            return

        if len(new_password) < 8:
            print("Password must be at least 8 characters long!")
            return

        # Create new password hash and cipher
        new_hashed_password = self._hash_password(new_password)
        new_salt = new_hashed_password[:32]
        new_key = self._derive_key_from_password(new_password, new_salt)
        new_cipher_suite = Fernet(new_key)

        # Re-encrypt all notes with new password
        re_encrypted_notes = {}
        for note_id, note_data in decrypted_notes.items():
            re_encrypted_notes[note_id] = {
                'title': new_cipher_suite.encrypt(note_data['title'].encode('utf-8')).decode('utf-8'),
                'content': new_cipher_suite.encrypt(note_data['content'].encode('utf-8')).decode('utf-8'),
                'created': note_data['created']
            }

        # Save new password and notes
        with open(self.password_file, 'wb') as f:
            f.write(new_hashed_password)

        self.save_notes(re_encrypted_notes)

        # Update current cipher suite
        self.cipher_suite = new_cipher_suite

        print("Password changed successfully!")

    def run(self):
        """Main application loop"""
        print("Welcome to Encrypted Notes App!")
        print("Your notes are stored in encrypted format and require authentication to view.")

        while True:
            print("\n=== MAIN MENU ===")
            print("1. View encrypted notes (no authentication)")
            print("2. Authenticate and access notes")
            print("3. Setup/Change password")
            print("4. Storage & Backup options")
            print("5. Exit")

            choice = input("Choose an option (1-5): ")

            if choice == '1':
                self.view_encrypted_notes()

            elif choice == '2':
                if self.authenticate():
                    self.authenticated_menu()

            elif choice == '3':
                if os.path.exists(self.password_file):
                    if self.authenticate():
                        self.change_password()
                else:
                    self.setup_password()

            elif choice == '4':
                self.storage_menu()

            elif choice == '5':
                print("Goodbye!")
                break

            else:
                print("Invalid option! Please choose 1-5.")

    def storage_menu(self):
        """Storage and backup management menu"""
        while True:
            print("\n=== STORAGE & BACKUP MENU ===")
            print("1. View storage information")
            print("2. Change storage location")
            print("3. Create backup")
            print("4. Export notes (requires authentication)")
            print("5. Back to main menu")

            choice = input("Choose an option (1-5): ")

            if choice == '1':
                self.get_storage_info()

            elif choice == '2':
                self.change_storage_location()

            elif choice == '3':
                self.backup_notes()

            elif choice == '4':
                if self.authenticated or self.authenticate():
                    self.export_notes()

            elif choice == '5':
                break

            else:
                print("Invalid option! Please choose 1-5.")

    def authenticated_menu(self):
        """Menu for authenticated users"""
        while True:
            print("\n=== AUTHENTICATED MENU ===")
            print("1. View decrypted notes")
            print("2. Add new note")
            print("3. Delete note")
            print("4. Change password")
            print("5. Export notes to text file")
            print("6. Logout")

            choice = input("Choose an option (1-6): ")

            if choice == '1':
                self.view_decrypted_notes()

            elif choice == '2':
                self.add_note()

            elif choice == '3':
                self.delete_note()

            elif choice == '4':
                self.change_password()

            elif choice == '5':
                self.export_notes()

            elif choice == '6':
                self.authenticated = False
                self.cipher_suite = None
                print("Logged out successfully!")
                break

            else:
                print("Invalid option! Please choose 1-6.")


def main():
    # For .exe distribution, you can set a default custom directory here
    # app = EncryptedNotesApp(custom_directory="C:\\MySecureNotes")
    app = EncryptedNotesApp()

    # Handle command line arguments for custom storage location
    if len(sys.argv) > 1:
        custom_dir = sys.argv[1]
        if os.path.exists(custom_dir):
            app = EncryptedNotesApp(custom_directory=custom_dir)
            print(f"Using custom storage directory: {custom_dir}")

    try:
        app.run()
    except KeyboardInterrupt:
        print("\n\nApplication interrupted by user. Goodbye!")
    except Exception as e:
        print(f"An error occurred: {e}")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()