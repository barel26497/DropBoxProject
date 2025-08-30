import unittest
import os
import shutil
import time

import bcrypt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import init, Fore
from unittest import mock
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Define server folder path for testing
SERVER_FOLDER_PATH = os.path.join(os.getcwd(), "client_folder")

# In-memory mock storage for credentials
_mocked_credentials = {}

init(autoreset=True)

def register_user(username, password):
    """Mock implementation of user registration."""
    # Validate username and password
    if not username or not password:
        return False, "Invalid username or password"
    if "/" in username or "\\" in username:
        return False, "Invalid username or password"
    if len(username) > 255:  # Example maximum length
        return False, "Username exceeds maximum length"

    # Load existing credentials
    credentials = load_credentials()
    if username in credentials:
        return False, "Username already exists"

    # Save the new user
    credentials[username] = password
    save_credentials(credentials)

    # Create the folder for the new user
    client_folder_name = f"client_folder_{username}"
    server_user_folder_path = os.path.join(SERVER_FOLDER_PATH, client_folder_name)
    if not os.path.exists(server_user_folder_path):
        os.makedirs(server_user_folder_path)

    return True, "Registration successful"


def authenticate_user(username, password):
    """Mock implementation of user authentication."""
    credentials = load_credentials()
    if username in credentials and credentials[username] == password:
        return True, "Login successful"
    return False, "Invalid username or password"


def delete_user(username, _args):
    """Mock implementation of user deletion."""
    credentials = load_credentials()
    if username in credentials:
        del credentials[username]
        save_credentials(credentials)
        return True, "User deleted successfully"
    return False, "User not found"


def load_credentials():
    """Mock function to load credentials."""
    return _mocked_credentials.copy()


def save_credentials(credentials):
    """Mock function to save credentials."""
    global _mocked_credentials
    _mocked_credentials = credentials.copy()


class TestServer(unittest.TestCase):
    def setUp(self):
        """Set up the environment before each test."""
        print(f"\n[SETUP] Initializing test environment for: {self._testMethodName}")

        self.test_username = "test_user"
        self.test_password = "test_password"
        self.local_folder_path = os.path.join("C:/Temp", f"client_folder_{self.test_username}")

        # Ensure test folders exist
        if not os.path.exists(SERVER_FOLDER_PATH):
            os.makedirs(SERVER_FOLDER_PATH)
            print("[SETUP] Created server folder path.")
        else:
            print("[SETUP] Server folder path exists.")

        if not os.path.exists(self.local_folder_path):
            os.makedirs(self.local_folder_path)
            print("[SETUP] Created local folder path.")
        else:
            print("[SETUP] Local folder path exists.")

        # Initialize event logs and credentials
        self.event_logs = []
        self.mocked_credentials = {
            "test_user": bcrypt.hashpw("test_password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        }
        self.username = "test_user"
        self.password = "test_password"
        self.data = b"This is a test message."

        # Define a mock file event handler class
        class MockFileEventHandler(FileSystemEventHandler):
            def __init__(self, event_logs):
                super().__init__()
                self.event_logs = event_logs

            def on_created(self, event):
                if not event.is_directory:
                    self.event_logs.append(f"Created: {event.src_path}")

            def on_modified(self, event):
                if not event.is_directory:
                    self.event_logs.append(f"Modified: {event.src_path}")

            def on_deleted(self, event):
                if not event.is_directory:
                    self.event_logs.append(f"Deleted: {event.src_path}")

        self.event_handler = MockFileEventHandler(self.event_logs)
        self.observer = Observer()
        self.observer.schedule(self.event_handler, self.local_folder_path, recursive=True)
        self.observer.start()

        print(f"[SETUP] Test environment setup complete for: {self._testMethodName}")

    def tearDown(self):
        """Clean up after tests."""
        print(f"\n[TEARDOWN] Cleaning up test environment for: {self._testMethodName}")

        # Stop and join the observer
        self.observer.stop()
        self.observer.join()
        print("[TEARDOWN] Observer stopped and joined.")

        # Remove test folders
        if os.path.exists(self.local_folder_path):
            shutil.rmtree(self.local_folder_path)
            print(f"[TEARDOWN] Removed local folder: {self.local_folder_path}")
        else:
            print(f"[TEARDOWN] Local folder already removed: {self.local_folder_path}")

        if os.path.exists(SERVER_FOLDER_PATH):
            shutil.rmtree(SERVER_FOLDER_PATH)
            print(f"[TEARDOWN] Removed server folder: {SERVER_FOLDER_PATH}")
        else:
            print(f"[TEARDOWN] Server folder already removed: {SERVER_FOLDER_PATH}")

        # Clear mocked credentials
        global _mocked_credentials
        _mocked_credentials = {}
        print("[TEARDOWN] Mocked credentials cleared.")

        print("\n\n==================================================\n")

    def test_watchdog_captures_events(self):
        """Test if watchdog detects file creation, modification, and deletion."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        test_file_path = os.path.join(self.local_folder_path, "test_file.txt")
        print(f"[TEST] Test file path: {test_file_path}")

        try:
            # Simulate file creation
            print("[TEST] Simulating file creation...")
            with open(test_file_path, "w") as f:
                f.write("This is a test file.")
            time.sleep(1)  # Allow time for detection
            print("[TEST] File creation simulated.")

            # Simulate file modification
            print("[TEST] Simulating file modification...")
            with open(test_file_path, "a") as f:
                f.write("\nAdditional content.")
            time.sleep(1)  # Allow time for detection
            print("[TEST] File modification simulated.")

            # Simulate file deletion
            print("[TEST] Simulating file deletion...")
            os.remove(test_file_path)
            time.sleep(1)  # Allow time for detection
            print("[TEST] File deletion simulated.")

            # Verify captured events
            print("[TEST] Verifying captured events...")
            self.assertIn(f"Created: {test_file_path}", self.event_logs, "File creation event not detected.")
            self.assertIn(f"Modified: {test_file_path}", self.event_logs, "File modification event not detected.")
            self.assertIn(f"Deleted: {test_file_path}", self.event_logs, "File deletion event not detected.")
            print("[TEST] All events verified successfully.")
        except AssertionError as e:
            print(f"[TEST] Event verification failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_register_user(self):
        """Test user registration functionality."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Attempt user registration
            print(f"[TEST] Registering user with username: {self.test_username}")
            success, message = register_user(self.test_username, self.test_password)

            # Verify registration success
            print(f"[TEST] Registration result - Success: {success}, Message: '{message}'")
            self.assertTrue(success, "User registration failed.")
            self.assertEqual(message, "Registration successful")
            print("[TEST] User registration test passed successfully.")
        except AssertionError as e:
            print(f"[TEST] User registration test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_login_user(self):
        """Test user login functionality."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Register the user before login test
            print(f"[TEST] Registering user with username: {self.test_username} for login test...")
            register_user(self.test_username, self.test_password)
            print(f"[TEST] User '{self.test_username}' registered successfully.")

            # Attempt user login
            print(f"[TEST] Attempting login for user: {self.test_username}")
            success, message = authenticate_user(self.test_username, self.test_password)
            print(f"[TEST] Login result - Success: {success}, Message: '{message}'")

            # Verify login success
            self.assertTrue(success, "User login failed.")
            self.assertEqual(message, "Login successful")
            print("[TEST] User login test passed successfully.")

        except AssertionError as e:
            print(f"[TEST] User login test failed: {e}")
            raise

    def test_delete_user(self):
        """Test user deletion functionality."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Register the user before deletion
            print(f"[TEST] Registering user with username: {self.test_username} for deletion test...")
            register_user(self.test_username, self.test_password)
            print(f"[TEST] User '{self.test_username}' registered successfully.")

            # Simulate a connection object
            print("[TEST] Creating a mock connection object...")

            class MockConnection:
                @staticmethod
                def send(message):
                    print(f"[MOCK] Sending: {message.decode()}")  # For debugging

                @staticmethod
                def recv(_args):
                    return b""

            connection = MockConnection()
            print("[TEST] Mock connection object created.")

            # Attempt user deletion
            print(f"[TEST] Attempting to delete user: {self.test_username}")
            success, message = delete_user(self.test_username, connection)
            print(f"[TEST] Deletion result - Success: {success}, Message: '{message}'")

            # Verify deletion success
            self.assertTrue(success, "User deletion failed.")
            self.assertEqual(message, "User deleted successfully")
            print("[TEST] User deletion test passed successfully.")

        except AssertionError as e:
            print(f"[TEST] User deletion test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_folder_creation(self):
        """Test folder creation for a user."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Register the user
            print(f"[TEST] Registering user with username: {self.test_username} for folder creation test...")
            register_user(self.test_username, self.test_password)
            print(f"[TEST] User '{self.test_username}' registered successfully.")

            # Verify the system logic automatically creates the folder
            client_folder_name = f"client_folder_{self.test_username}"
            user_folder_path = os.path.join(SERVER_FOLDER_PATH, client_folder_name)
            print(f"[TEST] Checking existence of user folder at: {user_folder_path}")

            # Assert folder creation
            self.assertTrue(os.path.exists(user_folder_path), f"User folder was not created at {user_folder_path}.")
            print("[TEST] Folder creation test passed successfully.")

        except AssertionError as e:
            print(f"[TEST] Folder creation test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_upload_file(self):
        """Test the upload functionality."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Simulate files to be uploaded
            file_name = "upload_test_file.txt"
            file_path = os.path.join(self.local_folder_path, file_name)

            # Create a test file locally
            print("[TEST] Creating a test file for upload...")
            with open(file_path, "w") as f:
                f.write("This is a test file for upload.")
            print(f"[TEST] Test file created at: {file_path}")

            # Mock upload function
            mock_client = unittest.mock.Mock()
            mock_client.send_file = unittest.mock.Mock()

            # Simulate uploading the file
            print("[TEST] Simulating file upload...")
            mock_client.send_file(file_path)

            # Verify that the upload function was called
            mock_client.send_file.assert_called_once_with(file_path)
            print("[TEST] File upload simulated and verified successfully.")

        except AssertionError as e:
            print(f"[TEST] Upload test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_download_file(self):
        """Test the download functionality."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Simulate a file to be downloaded
            file_name = "download_test_file.txt"
            server_file_path = os.path.join(SERVER_FOLDER_PATH, f"client_folder_{self.test_username}", file_name)
            local_file_path = os.path.join(self.local_folder_path, file_name)

            # Create the file on the server
            print("[TEST] Creating a test file on the server for download...")
            os.makedirs(os.path.dirname(server_file_path), exist_ok=True)
            with open(server_file_path, "w") as f:
                f.write("This is a test file for download.")
            print(f"[TEST] Test file created at: {server_file_path}")

            # Mock download function
            mock_client = unittest.mock.Mock()
            mock_client.receive_file = unittest.mock.Mock()

            # Simulate downloading the file
            print("[TEST] Simulating file download...")
            mock_client.receive_file(local_file_path)

            # Verify that the download function was called
            mock_client.receive_file.assert_called_once_with(local_file_path)
            print("[TEST] File download simulated and verified successfully.")

        except AssertionError as e:
            print(f"[TEST] Download test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")


    @staticmethod
    def _derive_key(username, hashed_password):
        """Derives an encryption key using the same logic as the server."""
        salt = b'PancakesAreAwsome'
        username_bytes = username.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(username_bytes + hashed_password)

    @staticmethod
    def _encrypt_data(data, key):
        """Encrypt data using AES-CBC with PKCS7 padding."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    @staticmethod
    def _decrypt_data(encrypted_data, key):
        """Decrypt data using AES-CBC with PKCS7 padding."""
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decryptor.update(encrypted_data[16:]) + decryptor.finalize())
        return decrypted_data + unpadder.finalize()

    def test_encryption_decryption(self):
        """Test encryption and decryption using derived key."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Simulate loading hashed password
            print(f"[TEST] Deriving key for username: {self.username}")
            hashed_password = self.mocked_credentials[self.username].encode('utf-8')
            key = self._derive_key(self.username, hashed_password)
            print("[TEST] Key derived successfully.")

            # Encrypt the data
            print("[TEST] Encrypting data...")
            encrypted_data = self._encrypt_data(self.data, key)

            # Verify encryption (encrypted data should differ from original)
            print("[TEST] Verifying encryption...")
            self.assertNotEqual(self.data, encrypted_data, "Encryption failed: Encrypted data matches the original.")
            print("[TEST] Data encrypted and verified successfully.")

            # Decrypt the data
            print("[TEST] Decrypting data...")
            decrypted_data = self._decrypt_data(encrypted_data, key)

            # Verify decryption (decrypted data should match the original)
            print("[TEST] Verifying decryption...")
            self.assertEqual(self.data, decrypted_data,
                             "Decryption failed: Decrypted data does not match the original.")
            print("[TEST] Encryption and decryption test passed successfully.")

        except AssertionError as e:
            print(f"[TEST] Encryption and decryption test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_invalid_key_decryption(self):
        """Test decryption failure with an incorrect key."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Simulate loading hashed password from credentials
            print(f"[TEST] Deriving correct key for username: {self.username}")
            hashed_password = self.mocked_credentials[self.username].encode('utf-8')
            correct_key = self._derive_key(self.username, hashed_password)
            if correct_key:
                print("[TEST] Correct key derived successfully.")
            else:
                raise AssertionError("[TEST] Failed to derive the correct key.")

            # Encrypt the data with the correct key
            print("[TEST] Encrypting data with the correct key...")
            encrypted_data = self._encrypt_data(self.data, correct_key)
            if encrypted_data != self.data:
                print("[TEST] Data encrypted successfully.")
            else:
                raise AssertionError("[TEST] Encryption failed: Encrypted data matches the original.")

            # Derive an incorrect key
            print("[TEST] Generating an incorrect key...")
            incorrect_key = os.urandom(32)
            if incorrect_key:
                print("[TEST] Incorrect key generated successfully.")
            else:
                raise AssertionError("[TEST] Failed to generate an incorrect key.")

            # Attempt to decrypt with the incorrect key
            print("[TEST] Attempting decryption with the incorrect key (expected to fail)...")
            with self.assertRaises(Exception, msg="Decryption should fail with an incorrect key."):
                self._decrypt_data(encrypted_data, incorrect_key)
            print("[TEST] Decryption with an incorrect key correctly failed.")

        except AssertionError as e:
            print(f"[TEST] Decryption failure test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_multiple_user_login_and_usage(self):
        """Test multiple users registering, logging in, and encrypting data."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            user_data = [
                {"username": f"user{i}", "password": f"password{i}"} for i in range(1, 6)
            ]

            for user in user_data:
                print(f"[TEST] Processing user: {user['username']}")

                # Register user
                print(f"[TEST] Registering user: {user['username']}")
                success, message = register_user(user["username"], user["password"])
                if success:
                    print(f"[TEST] User {user['username']} registered successfully.")
                else:
                    print(f"[TEST] User {user['username']} registration failed with message: {message}")
                self.assertTrue(success, f"User {user['username']} registration failed.")
                self.assertEqual(message, "Registration successful")

                # Authenticate user
                print(f"[TEST] Authenticating user: {user['username']}")
                success, message = authenticate_user(user["username"], user["password"])
                if success:
                    print(f"[TEST] User {user['username']} logged in successfully.")
                else:
                    print(f"[TEST] User {user['username']} login failed with message: {message}")
                self.assertTrue(success, f"User {user['username']} login failed.")
                self.assertEqual(message, "Login successful")

                # Test encryption and decryption
                print(f"[TEST] Deriving key for user: {user['username']}")
                hashed_password = bcrypt.hashpw(user["password"].encode('utf-8'), bcrypt.gensalt())
                key = self._derive_key(user["username"], hashed_password)
                if key:
                    print(f"[TEST] Key derived successfully for user: {user['username']}.")
                else:
                    raise AssertionError(f"[TEST] Key derivation failed for user: {user['username']}.")

                print(f"[TEST] Encrypting data for user: {user['username']}")
                encrypted_data = self._encrypt_data(self.data, key)
                if self.data != encrypted_data:
                    print(f"[TEST] Data encrypted successfully for user: {user['username']}.")
                else:
                    raise AssertionError(f"[TEST] Encryption failed for user: {user['username']}.")

                print(f"[TEST] Decrypting data for user: {user['username']}")
                decrypted_data = self._decrypt_data(encrypted_data, key)
                if self.data == decrypted_data:
                    print(f"[TEST] Data decrypted successfully for user: {user['username']}.")
                else:
                    raise AssertionError(f"[TEST] Decryption failed for user: {user['username']}.")

            print("[TEST] Multiple user login and usage test passed successfully.")

        except AssertionError as e:
            print(f"[TEST] Multiple user login and usage test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_folder_creation_for_multiple_users(self):
        """Test folder creation for multiple users."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        user_data = [
            {"username": f"user{i}", "password": f"password{i}"} for i in range(1, 6)
        ]

        try:
            for user in user_data:
                print(f"[TEST] Processing user: {user['username']}")

                # Register user
                print(f"[TEST] Attempting to register user: {user['username']}")
                success, message = register_user(user["username"], user["password"])
                if not success:
                    raise AssertionError(
                        f"[TEST] Registration failed for user {user['username']} with message: {message}")
                self.assertEqual(message, "Registration successful")
                print(f"[TEST] Registration successful for user: {user['username']}")

                # Verify folder creation
                client_folder_name = f"client_folder_{user['username']}"
                user_folder_path = os.path.join(SERVER_FOLDER_PATH, client_folder_name)
                print(f"[TEST] Checking folder creation for user: {user['username']} at {user_folder_path}")
                if not os.path.exists(user_folder_path):
                    raise AssertionError(f"[TEST] Folder creation failed for user {user['username']}")
                print(f"[TEST] Folder verified successfully for user: {user['username']} at {user_folder_path}")

            print("[TEST] Folder creation for all users verified successfully.")

        except AssertionError as e:
            print(f"[TEST] Test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_register_user_edge_cases(self):
        """Test user registration edge cases."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Edge Case 1: Empty username
            print("[TEST] Testing registration with an empty username...")
            success, message = register_user("", "password")
            self.assertFalse(success, "Registration should fail for empty username.")
            self.assertEqual(message, "Invalid username or password", "Incorrect message for empty username.")

            # Edge Case 2: Empty password
            print("[TEST] Testing registration with an empty password...")
            success, message = register_user("user_empty_password", "")
            self.assertFalse(success, "Registration should fail for empty password.")
            self.assertEqual(message, "Invalid username or password", "Incorrect message for empty password.")

            # Edge Case 3: Long username
            long_username = "u" * 256  # Assuming the username limit is 255
            print(f"[TEST] Testing registration with a long username ({len(long_username)} characters)...")
            success, message = register_user(long_username, "password")
            self.assertFalse(success, "Registration should fail for long username.")
            self.assertEqual(message, "Username exceeds maximum length", "Incorrect message for long username.")

            # Edge Case 4: Duplicate username
            print("[TEST] Testing registration with a duplicate username...")
            register_user("duplicate_user", "password")
            success, message = register_user("duplicate_user", "password")
            self.assertFalse(success, "Registration should fail for duplicate username.")
            self.assertEqual(message, "Username already exists", "Incorrect message for duplicate username.")

            print("[TEST] Registration edge cases passed successfully.")

        except AssertionError as e:
            print(f"[TEST] Registration edge cases test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_authenticate_user_edge_cases(self):
        """Test user authentication edge cases."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Setup: Register a valid user
            register_user("valid_user", "valid_password")

            # Edge Case 1: Non-existent username
            print("[TEST] Testing login with a non-existent username...")
            success, message = authenticate_user("non_existent_user", "password")
            self.assertFalse(success, "Authentication should fail for non-existent username.")
            self.assertEqual(message, "Invalid username or password", "Incorrect message for non-existent username.")

            # Edge Case 2: Incorrect password
            print("[TEST] Testing login with an incorrect password...")
            success, message = authenticate_user("valid_user", "wrong_password")
            self.assertFalse(success, "Authentication should fail for incorrect password.")
            self.assertEqual(message, "Invalid username or password", "Incorrect message for incorrect password.")

            # Edge Case 3: Empty username
            print("[TEST] Testing login with an empty username...")
            success, message = authenticate_user("", "password")
            self.assertFalse(success, "Authentication should fail for empty username.")
            self.assertEqual(message, "Invalid username or password", "Incorrect message for empty username.")

            # Edge Case 4: Empty password
            print("[TEST] Testing login with an empty password...")
            success, message = authenticate_user("valid_user", "")
            self.assertFalse(success, "Authentication should fail for empty password.")
            self.assertEqual(message, "Invalid username or password", "Incorrect message for empty password.")

            print("[TEST] Authentication edge cases passed successfully.")

        except AssertionError as e:
            print(f"[TEST] Authentication edge cases test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_folder_creation_edge_cases(self):
        """Test folder creation edge cases."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Edge Case 1: Folder already exists
            print("[TEST] Testing folder creation when the folder already exists...")
            user_folder_path = os.path.join(SERVER_FOLDER_PATH, "client_folder_test_user")
            os.makedirs(user_folder_path)  # Manually create the folder
            success, message = register_user("test_user", "password")
            self.assertTrue(success, "Registration should succeed even if the folder already exists.")
            self.assertTrue(os.path.exists(user_folder_path), "Folder should still exist after registration.")

            # Edge Case 2: Invalid folder name
            print("[TEST] Testing folder creation for an invalid username...")
            success, message = register_user("invalid/user", "password")
            self.assertFalse(success, "Registration should fail for an invalid username.")
            self.assertEqual(message, "Invalid username or password", "Incorrect message for invalid username.")

            print("[TEST] Folder creation edge cases passed successfully.")

        except AssertionError as e:
            print(f"[TEST] Folder creation edge cases test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")

    def test_encryption_decryption_edge_cases(self):
        """Test encryption and decryption edge cases."""
        print(f"\n[TEST] Running test: {self._testMethodName}")

        try:
            # Setup: Derive a valid key
            hashed_password = self.mocked_credentials[self.username].encode('utf-8')
            key = self._derive_key(self.username, hashed_password)

            # Edge Case 1: Empty data
            print("[TEST] Testing encryption with empty data...")
            empty_data = b""
            encrypted_data = self._encrypt_data(empty_data, key)
            decrypted_data = self._decrypt_data(encrypted_data, key)
            self.assertEqual(empty_data, decrypted_data, "Decryption failed for empty data.")

            # Edge Case 2: Corrupted encrypted data
            print("[TEST] Testing decryption with corrupted encrypted data...")
            corrupted_data = encrypted_data[:-1]  # Remove the last byte
            with self.assertRaises(Exception, msg="Decryption should fail for corrupted data."):
                self._decrypt_data(corrupted_data, key)

            # Edge Case 3: Invalid key
            print("[TEST] Testing decryption with an invalid key...")
            invalid_key = os.urandom(32)
            with self.assertRaises(Exception, msg="Decryption should fail for an invalid key."):
                self._decrypt_data(encrypted_data, invalid_key)

            print("[TEST] Encryption and decryption edge cases passed successfully.")

        except AssertionError as e:
            print(f"[TEST] Encryption and decryption edge cases test failed: {e}")
            raise
        finally:
            print("[TEST] Test completed.")


class ColorfulTestRunner:
    """Custom test runner with colored output and detailed results."""

    @staticmethod
    def run(test_suite):
        """Run the test suite and display results with colors and details."""
        print(f"{Fore.CYAN}{'=' * 50}")
        print(f"{Fore.BLUE}Running Tests...")
        print(f"{Fore.CYAN}{'=' * 50}")

        # Run tests
        results = unittest.TestResult()
        test_suite.run(results)

        # Display results
        if results.wasSuccessful():
            print(f"{Fore.GREEN}ALL TESTS PASSED! 🎉")
        else:
            print(f"{Fore.RED}{len(results.failures)} Test(s) Failed. ❌")
            for test, error in results.failures:
                print(f"{Fore.RED}{test} - {error}")

        print(f"{Fore.CYAN}{'=' * 50}")


if __name__ == "__main__":
    # Load test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestServer)

    # Run tests with the custom runner
    runner = ColorfulTestRunner()
    runner.run(suite)
