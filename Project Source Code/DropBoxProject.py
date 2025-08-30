import platform
import signal
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import os
import ssl
import socket
import threading
import shutil
import time
from tkinterdnd2 import DND_FILES, TkinterDnD
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PIL import Image, ImageTk
import stat
import fitz
import logging
from typing import cast

CA_FILE = "ca.pem"  # The CA certificate to verify the server

# Determine the current directory dynamically
if getattr(sys, 'frozen', False):  # Check if running as a frozen .exe
    # Get the current directory and define the absolute path for the cert file
    current_directory = os.path.dirname(sys.executable)  # Path to the .exe directory
else:
    current_directory = os.path.dirname(os.path.abspath(__file__))  # Path to the .py directory

# Minimal change: Dynamically set the icons folder path
if hasattr(sys, '_MEIPASS'):
    icons_folder_path = os.path.join(sys._MEIPASS, "icons")
else:
    icons_folder_path = os.path.join(os.path.abspath("."), "icons")

# Set the logging level for the "PIL" logger to INFO
logging.getLogger("PIL").setLevel(logging.INFO)

def discover_server_ip(broadcast_port=12345, timeout=10):
    """
    Listens for a broadcast message from the server to discover its IP address.
    Args:
        broadcast_port (int): The port to listen for broadcast messages.
        timeout (int): Time in seconds to wait for a broadcast before giving up.

    Returns:
        str: The server's IP address if found.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', broadcast_port))  # Listen for broadcasts on the given port
        sock.settimeout(timeout)  # Set a timeout to avoid indefinite waiting

        try:
            print(f"Listening for server broadcast on port {broadcast_port} (timeout: {timeout}s)...")
            data, addr = sock.recvfrom(1024)  # Wait for broadcast
            print(f"Discovered server IP: {data.decode()} from {addr}")
            return data.decode()  # Return the discovered IP
        except socket.timeout:
            sys.exit("Failed to discover server IP. Ensure the server is broadcasting.")


# Client Configuration
SERVER_PORT = 465
BUFFER_SIZE = 1024
SERVER_HOST = discover_server_ip()


class Client:
    def __init__(self, host=SERVER_HOST, port=SERVER_PORT):
        """
           Initializes the Client object with server connection details.

           Args:
               host (str): The server's hostname or IP address.
               port (int): The server's port number for the connection.
        """
        self.host = host
        self.port = port
        # Create a TCP socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        """
            Establishes a secure SSL/TLS connection to the server.

            Raises:
                ssl.SSLError: If an SSL-related error occurs during the handshake.
                socket.error: If the connection to the server fails.
        """
        # Create an SSL context for secure communication
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load the CA certificate to verify the server
        ssl_context.load_verify_locations(CA_FILE)

        # Create a raw socket connection
        with socket.create_connection((SERVER_HOST, SERVER_PORT)) as raw_socket:
            # Wrap the socket with SSL for secure communication
            with ssl_context.wrap_socket(raw_socket, server_hostname=SERVER_HOST) as ssl_socket:
                print(f"[CONNECTED] Secure connection established with {SERVER_HOST}:{SERVER_PORT}")

                # Example interaction
                ssl_socket.sendall(b"Hello, server!")
                response = ssl_socket.recv(1024).decode()
                print(f"[SERVER RESPONSE] {response}")

    def login(self, username, password):
        """
            Attempts to log in to the server using provided credentials.

            Args:
                username (str): The username for login.
                password (str): The password for login.

            Returns:
                bool: True if login is successful, False otherwise.
        """
        print("Attempting login...")  # Debugging start of login attempt
        try:
            # Check if the socket is already connected and close it if necessary
            if self.client_socket:
                try:
                    # If connected, attempt to shut down and close the existing socket
                    print("Closing stale connection before reattempting login...")
                    self.client_socket.shutdown(socket.SHUT_RDWR)
                    self.client_socket.close()
                except Exception as error_name:
                    print(f"Error shutting down previous socket: {error_name}")
                finally:
                    self.client_socket = None  # Ensure the socket is reset

            # Create a new socket and establish a secure connection
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_verify_locations(CA_FILE)
            self.client_socket = context.wrap_socket(self.client_socket, server_hostname=self.host)

            # Connect to the server
            print("Connecting to server...")
            self.client_socket.connect((self.host, 465))
            print(f"[CONNECTED] Connected to server at {self.host}:465")

            # Proceed with login attempt
            self.client_socket.send("login".encode())
            self.client_socket.recv(1024).decode().strip()  # Acknowledge login
            self.client_socket.send(f"{username},{password}".encode())
            response = self.client_socket.recv(1024).decode()
            print(response)

            if "Login successful" in response:
                print("Login succeeded.")
                return True
            elif "Invalid username or password" in response:
                print("Invalid credentials.")
                return False
            else:
                print(f"Unexpected server response: {response}")
                return False

        except Exception as error_name:
            print(f"Error during login: {str(error_name)}")
            return False

    def register(self, username, password):
        """
            Registers a new user with the server.

            Args:
                username (str): The desired username for registration.
                password (str): The desired password for registration.

            Returns:
                bool: True if registration is successful, False otherwise.
        """

        # Check if the socket is already connected and close it if necessary
        if self.client_socket:
            try:
                print("Closing stale connection before attempting registration...")
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except Exception as error_name:
                print(f"Error shutting down previous socket: {error_name}")
            finally:
                self.client_socket = None  # Ensure the socket is reset

        try:
            # Create a new socket and establish a secure connection
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_verify_locations(CA_FILE)
            self.client_socket = context.wrap_socket(self.client_socket, server_hostname=self.host)

            # Connect to the server
            print(f"Connecting to {self.host}:{self.port}...")
            self.client_socket.connect((self.host, self.port))

            # Send registration command
            self.client_socket.send(f"register".encode())
            self.client_socket.recv(1024).decode().strip()

            # Send credentials
            self.client_socket.send(f"{username},{password}".encode())
            response = self.client_socket.recv(1024).decode()
            print(response)

            if "successful" in response:
                print("You can now perform actions on the server.")
                return True

        except Exception as e:
            print(f"An error occurred during registration: {e}")
            self.client_socket = None  # Reset socket on failure

        return False


    def send_file(self, file_path):
        """
            Sends a file to the server.

            Args:
                file_path (str): The full path of the file to be sent.

            Returns:
                bool: True if the file is successfully sent, False otherwise.
        """
        # Extract file name from path
        file_name = os.path.basename(file_path)

        # Get the file size in bytes
        file_size = os.path.getsize(file_path)

        # Send file metadata to the server
        self.client_socket.send(f"SEND_FILE,{file_name},{file_size}".encode())

        # Wait for server ready signal
        response = self.client_socket.recv(1024).decode().strip()
        if not response.startswith("READY"):
            print("Server not ready to receive file.")
            return False

        # Send file data in chunks
        bytes_sent = 0
        try:
            with open(file_path, 'rb') as file:
                while bytes_sent < file_size:
                    # Read a chunk of the file
                    chunk = file.read(BUFFER_SIZE)
                    if not chunk:
                        break

                    # Send the chunk
                    self.client_socket.send(chunk)
                    bytes_sent += len(chunk)
                    # print(f"Sent {bytes_sent} bytes of {file_size}")

            # Send EOF signal to indicate the end of the file transfer
            self.client_socket.send(b"EOF")
            print(f"Sent EOF for {file_name}")

            # Receive acknowledgment from the server
            ack = self.client_socket.recv(1024).decode().strip()
            if ack != "ACK":
                print(f"Error: No ACK received for {file_name}")
                return False

            print(f"File {file_name} sent successfully.")
            return True

        except Exception as error_name:
            print(f"Error while sending file {file_name}: {error_name}")
            return False

    def receive_file(self, save_path):
        """
            Receives a file from the server.

            Args:
                save_path (str): The directory where the received file should be saved.

            Returns:
                bool: True if the file is successfully received, False otherwise.
        """
        # Receive file metadata from the server
        file_info = self.client_socket.recv(1024).decode().split(',')
        if file_info[0] != "RECEIVE":
            print("Unexpected server response.")
            return False

        file_name, file_size = file_info[1], int(file_info[2])

        # Send ready signal (binary mode)
        self.client_socket.send(b"READY")

        # Receive file data (binary mode)
        file_path = os.path.join(save_path, file_name)
        with open(file_path, 'wb') as file:
            bytes_received = 0
            while bytes_received < file_size:
                chunk = self.client_socket.recv(min(BUFFER_SIZE, file_size - bytes_received))
                file.write(chunk)
                bytes_received += len(chunk)

        print(f"File {file_name} received successfully.")
        return True

    def close(self):
        """
            Closes the connection to the server.
        """
        try:
            if self.client_socket:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            self.client_socket = None
        except OSError as e:
            print(f"Error shutting down socket: {e}")


class OfflineClient:
    """
        A client class for handling offline operations when the server is unavailable.
        Provides user feedback through message boxes for unsupported server operations.
    """

    @staticmethod
    def login(*_args, **_kwargs):
        """
            Simulates a login operation in offline mode.

            Returns:
                bool: Always returns True to allow offline mode operations.
        """
        messagebox.showinfo("Offline Mode", "You are in offline mode. No server operations available.")
        return True

    @staticmethod
    def register(*_args, **_kwargs):
        """
            Simulates a registration attempt in offline mode.

            Returns:
                bool: Always returns False since registration is not possible in offline mode.
        """
        messagebox.showinfo("Offline Mode", "Cannot register in offline mode.")
        return False

    @staticmethod
    def send_file(*_args):
        """
            Simulates a file upload operation in offline mode.

            Returns:
                bool: Always returns False since file uploads are not supported in offline mode.
        """
        messagebox.showinfo("Offline Mode", "Cannot send files to server in offline mode.")
        return False

    @staticmethod
    def receive_file(*_args):
        """
            Simulates a file download operation in offline mode.

            Returns:
                bool: Always returns False since file downloads are not supported in offline mode.
        """
        messagebox.showinfo("Offline Mode", "Cannot receive files in offline mode.")
        return False

    @staticmethod
    def send():
        """
            Simulates a generic send operation in offline mode.

            Returns:
                bool: Always returns False since sending is not supported in offline mode.
        """
        messagebox.showinfo("Offline Mode", "Cant send in offline mode.")
        return False

    @staticmethod
    def close():
        """
            Closes the offline client. Prints a message indicating the client is closed.

            Returns:
                None
        """
        print("[INFO] Offline client closed.")


class LoginSignupScreen(tk.Tk):
    """
       Represents the login and signup GUI screen for the application.
       Allows users to log in, create a new account, and transition to the main application.

       Attributes:
           client: The client object used for communicating with the server.
           container: The main frame container for the login/signup screens.
           login_frame: The frame displaying the login UI.
           signup_frame: The frame displaying the signup UI.
   """

    def __init__(self, client):
        """
            Initializes the LoginSignupScreen.

            Args:
                client: The client object used for backend operations.
        """
        super().__init__()
        self.title("Welcome")
        self.geometry("400x500")  # Set window dimensions
        self.configure(bg="#ffffff")  # Set background color
        self.client = client  # Save the client object for backend interactions

        # Placeholders for dynamic attributes
        self.username_entry = None
        self.password_entry = None
        self.new_username_entry = None
        self.new_password_entry = None
        self.confirm_password_entry = None
        self.signup_frame = None
        self.login_frame = None
        self.current_app = None

        # Create the main container frame for switching between login and signup
        self.container = tk.Frame(self, bg="#ffffff")
        self.container.pack(expand=True, fill="both", padx=40, pady=20)

        # Initialize frames
        self.login_frame = None
        self.signup_frame = None

        # Show the login screen by default
        self.show_login()

    def create_styled_entry(self, parent, placeholder):
        """
           Creates a styled entry field with placeholder text.

           Args:
               parent: The parent widget to which the entry belongs.
               placeholder: Placeholder text to display in the entry field.

           Returns:
               tk.Entry: A styled entry widget.
       """

        # Define the styling for the entry widget
        entry_style = {
            'font': ('Helvetica', 12),
            'bg': '#f8f9fa',
            'relief': 'flat',
            'width': 25
        }

        # Create a container frame for the entry
        frame = tk.Frame(parent, bg="#ffffff", height=45)
        frame.pack(fill='x', pady=5)
        frame.pack_propagate(False)

        # Create the entry widget
        entry = tk.Entry(frame, **entry_style)
        entry.pack(fill='x', pady=5)

        # Set the placeholder and configure focus events
        entry.insert(0, placeholder)
        entry.bind('<FocusIn>', lambda e: self.on_entry_click(entry, placeholder))
        entry.bind('<FocusOut>', lambda e: self.on_focus_out(entry, placeholder))

        return entry

    @staticmethod
    def create_styled_button(parent, text, command, primary=True):
        """
            Creates a styled button for actions like login or signup.

            Args:
                parent: The parent widget to which the button belongs.
                text (str): The text to display on the button.
                command: The function to call when the button is clicked.
                primary (bool): Whether the button is a primary action button.

            Returns:
                tk.Button: A styled button widget.
        """

        # Check if the button is primary or secondary
        if primary:
            # Create a primary button with blue styling
            button = tk.Button(parent, text=text, command=command,
                               font=('Helvetica', 12, 'bold'),
                               bg="#007bff", fg="white",
                               activebackground="#0056b3",
                               activeforeground="white",
                               relief="flat",
                               width=20, height=2)
        else:
            # Create a secondary button with white background and blue text
            button = tk.Button(parent, text=text, command=command,
                               font=('Helvetica', 12),
                               bg="#ffffff", fg="#007bff",
                               activebackground="#f8f9fa",
                               activeforeground="#007bff",
                               relief="flat",
                               width=20, height=2)
        return button

    def show_login(self):
        """
           Displays the login screen by creating a login frame.
           Destroys any existing signup frame before creating the login frame.
       """

        # Remove the signup frame if it exists
        if self.signup_frame:
            self.signup_frame.destroy()

        # Create a new frame for the login screen
        self.login_frame = tk.Frame(self.container, bg="#ffffff")
        self.login_frame.pack(expand=True, fill="both")

        # Add a header label to the login screen
        tk.Label(self.login_frame, text="Welcome Back!",
                 font=("Helvetica", 24, "bold"),
                 bg="#ffffff", fg="#212529").pack(pady=20)

        # Create and add input fields for username and password
        self.username_entry = self.create_styled_entry(self.login_frame, "Username")
        self.password_entry = self.create_styled_entry(self.login_frame, "Password")

        # Add login and create account buttons
        self.create_styled_button(self.login_frame, "Login", self.check_credentials).pack(pady=20)
        self.create_styled_button(self.login_frame, "Create Account", self.show_signup, primary=False).pack()

    def show_signup(self):
        """
            Displays the signup screen by creating a signup frame.
            Destroys any existing login frame before creating the signup frame.
        """

        # Remove the login frame if it exists
        if self.login_frame:
            self.login_frame.destroy()

        # Create a new frame for the signup screen
        self.signup_frame = tk.Frame(self.container, bg="#ffffff")
        self.signup_frame.pack(expand=True, fill="both")

        # Add a header label to the signup screen
        tk.Label(self.signup_frame, text="Create Account",
                 font=("Helvetica", 24, "bold"),
                 bg="#ffffff", fg="#212529").pack(pady=20)

        # Create and add input fields for username, password, and confirmation
        self.new_username_entry = self.create_styled_entry(self.signup_frame, "Username")
        self.new_password_entry = self.create_styled_entry(self.signup_frame, "Password")
        self.confirm_password_entry = self.create_styled_entry(self.signup_frame, "Confirm Password")

        # Add sign-up and back-to-login buttons
        self.create_styled_button(self.signup_frame, "Sign Up", self.register_user).pack(pady=20)
        self.create_styled_button(self.signup_frame, "Back to Login", self.show_login, primary=False).pack()

    @staticmethod
    def on_entry_click(entry, placeholder):
        """
            Clears the placeholder text when the entry gains focus.

            Args:
                entry: The entry widget gaining focus.
                placeholder: The placeholder text to clear.
        """

        # Check if the placeholder is still present
        if entry.get() == placeholder:
            # Clear the placeholder text
            entry.delete(0, tk.END)

            # If it's a password field
            if "Password" in placeholder:
                # Mask input characters
                entry.config(show="*")

    @staticmethod
    def on_focus_out(entry, placeholder):
        """
            Restores the placeholder text if the entry is empty on losing focus.

            Args:
                entry: The entry widget losing focus.
                placeholder: The placeholder text to restore.
        """
        # Check if the entry is empty
        if entry.get() == "":
            # Restore the placeholder
            entry.insert(0, placeholder)

            # If it's a password field
            if "Password" in placeholder:
                if entry.get() == placeholder:
                    # Unmask input for the placeholder
                    entry.config(show="")

    @staticmethod
    def screen_cleaning(user_screen, password_screen):
        """
            Resets the username and password fields to their placeholder states.

            Args:
                user_screen: The username entry widget.
                password_screen: The password entry widget.
        """
        # Clear all text in the username entry field
        user_screen.delete(0, tk.END)

        # Insert the placeholder text for the username
        user_screen.insert(0, "Username")

        # Ensure the text in the username field is visible (not masked)
        user_screen.config(show="")

        # Clear all text in the password entry field
        password_screen.delete(0, tk.END)

        # Insert the placeholder text for the password
        password_screen.insert(0, "Password")

        # Ensure the text in the password field is unmasked (visible)
        password_screen.config(show="")

        # Set focus back to the username field for the user's convenience
        user_screen.focus()

    def check_credentials(self):
        """
            Verifies the user's login credentials with the server.

            Shows appropriate messages for success or failure.
        """

        # Get the entered username
        username = self.username_entry.get()

        # Get the entered password
        password = self.password_entry.get()

        # Check if placeholders are unchanged
        if username == "Username" or password == "Password":
            # Show error
            messagebox.showerror("Error", "Please enter your credentials")

            # Reset fields
            self.screen_cleaning(self.username_entry, self.password_entry)
            return

        try:
            # Attempt to log in using the client
            if self.client.login(username, password):
                messagebox.showinfo("Success", "Welcome back!")
                self.destroy()  # Close login screen
                self.open_main_app(username)  # Open main app with authenticated user
            else:
                # For any other response, show a generic login error
                messagebox.showerror("Error", "Invalid username or password")
                self.screen_cleaning(self.username_entry, self.password_entry)
        except Exception as error_name:
            # If an exception occurs, it's likely due to a connection or unexpected response
            messagebox.showerror("Error", f"An unexpected error occurred: {str(error_name)}")

    def register_user(self):
        """
            Handles user registration by validating input fields, ensuring passwords match,
            and attempting to register the user with the server.

            Validates inputs, shows error messages for invalid data, and displays
            success messages for successful registration.
        """

        # Get input values from the entry fields
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        # Check if any field still contains placeholder text
        if username == "Username" or password == "Password" or confirm_password == "Confirm Password":
            # Show error if placeholders are still present (fields are empty)
            messagebox.showerror("Error", "Please fill all fields")

            # Reset username and password fields to placeholders
            self.screen_cleaning(self.new_username_entry, self.new_password_entry)

            # Reset the confirmation password field
            self.confirm_password_entry.delete(0, tk.END)
            self.confirm_password_entry.insert(0, "Confirm Password")
            self.confirm_password_entry.config(show="")

            return

        # Check if passwords match
        if password != confirm_password:
            # Show error if the passwords do not match
            messagebox.showerror("Error", "Passwords do not match")
            return

        # Attempt to register the user with the server
        if self.client.register(username, password):
            # Show success message if registration is successful
            messagebox.showinfo("Success", "Your account has been created!")
            # Navigate to the login screen
            self.show_login()
        else:
            # Show error if registration fails (e.g., invalid credentials or username taken)
            messagebox.showerror("Error", "Invalid username or password")

    def open_main_app(self, username):
        """
            Opens the main application GUI after a successful login or registration.

            Args:
                username (str): The username of the authenticated user.
        """

        # Create and launch the main application window
        self.current_app = DropboxGUI(self.client, username, self)
        self.current_app.mainloop()


class FileEventHandler(FileSystemEventHandler):
    """
       A custom event handler for monitoring file system changes and updating the GUI treeview accordingly.

       Attributes:
           tree: The treeview widget in the GUI used to display files and their statuses.
           is_gui_action (bool): A flag to differentiate between GUI-initiated actions and external changes.
   """

    def __init__(self, tree):
        """
            Initializes the FileEventHandler with a reference to the treeview.

            Args:
                tree: The GUI treeview widget to be updated on file system events.
        """
        # Calling __init__ method in FileSystemEventHandler (Parent)
        super().__init__()
        # Reference to the treeview widget
        self.tree = tree
        # Flag to ignore GUI-initiated file changes
        self.is_gui_action = False

    def on_deleted(self, event):
        """
            Handles file deletion events. Removes the deleted file from the treeview.

            Args:
                event: The file system event object for the deleted file.
        """
        # Ignore directories and GUI-initiated deletions
        if not event.is_directory and not self.is_gui_action:
            print(f"[DEBUG] on_deleted triggered for: {event.src_path}")

            # Ensure the treeview still exists
            if hasattr(self.tree, 'get_children'):
                # Iterate through the items in the treeview
                for item in self.tree.get_children():
                    # Check if the file path matches the deleted file
                    if self.tree.item(item, "values")[3] == event.src_path:
                        print("File deleted outside of GUI:", event.src_path)
                        # Remove the item from the treeview
                        self.tree.delete(item)
                        # Exit loop once the file is found
                        break

    def on_modified(self, event):
        """
            Handles file modification events. Updates the file's status in the treeview to "Not Synced."

            Args:
                event: The file system event object for the modified file.
        """
        # Ignore directories and GUI-initiated modifications
        if not self.is_gui_action:
            # Iterate through the items in the treeview
            for item in self.tree.get_children():
                # Check if the file path matches the modified file
                if self.tree.item(item, "values")[3] == event.src_path:
                    print(f"Modified: {event.src_path}")
                    # Update the treeview
                    self.update_tree_item(item, event.src_path, "Not Synced")  # Mark as Not Synced
                    # Exit loop once the file is found
                    break

    def on_created(self, event):
        """
            Handles file creation events. Adds the newly created file to the treeview.

            Args:
                event: The file system event object for the created file.
        """
        # Ignore directories and GUI-initiated creations
        if not self.is_gui_action:
            print(f"ON Created: {event.src_path}")
            # Add the new file to the treeview
            self.add_file_to_tree(event.src_path, "Not Synced")  # Mark as Not Synced

    def on_moved(self, event):
        """
            Handles file move/rename events. Updates the file path in the treeview.

            Args:
                event: The file system event object for the moved file.
        """
       # Ignore directories and GUI-initiated moves
        if not self.is_gui_action:
            old_path = event.src_path  # Original file path
            new_path = event.dest_path  # New file path

            # Iterate through the items in the treeview
            for item in self.tree.get_children():
                # Check if the file path matches the old path
                if self.tree.item(item, "values")[3] == old_path:
                    print(f"[INFO] File moved/renamed from {old_path} to {new_path}")
                    # Update the treeview with the new path
                    self.update_tree_item(item, new_path, "Not Synced")
                    # Exit method after updating the moved file
                    return

            # If the moved file was not previously tracked
            print(f"[INFO] Moved file not tracked previously: {new_path}")
            # Add the new file to the treeview
            self.add_file_to_tree(new_path, "Not Synced")

    def update_tree_item(self, item, file_path, status):
        """
            Updates an existing item in the treeview with new details.

            Args:
                item: The treeview item to update.
                file_path (str): The file path of the updated item.
                status (str): The new status to set (e.g., "Not Synced").
        """
        # Extract the file name from the path
        file_name = os.path.basename(file_path)
        # Get the last modified timestamp
        modified_time = os.path.getmtime(file_path)
        # Convert timestamp to human-readable format
        modified_time_str = time.ctime(modified_time)

        # Update the treeview item with new values
        self.tree.item(item, values=(file_name, status, modified_time_str, file_path))

    def add_file_to_tree(self, file_path, status="Not Synced"):
        """
           Adds a new file to the treeview.

           Args:
               file_path (str): The full path of the file to add.
               status (str): The status of the file (default: "Not Synced").
        """
        # Extract the file name from the path
        file_name = os.path.basename(file_path)
        # Get the last modified timestamp
        modified_time = os.path.getmtime(file_path)
        # Convert timestamp to human-readable format
        modified_time_str = time.ctime(modified_time)

        # Check if the file is already in the treeview
        if file_path not in [self.tree.item(item, "values")[3] for item in self.tree.get_children()]:
            # Add the new file to the treeview
            self.tree.insert("", tk.END, values=(file_name, status, modified_time_str, file_path))

    def mark_as_synced(self, file_path):
        """
            Marks a file as "Synced" in the treeview after a successful sync operation.

            Args:
                file_path (str): The file path of the synced file.
        """
        # Iterate through the items in the treeview
        for item in self.tree.get_children():
            # Check if the file path matches the given file
            if self.tree.item(item, "values")[3] == file_path:
                # Update the file's status to "Synced"
                self.update_tree_item(item, file_path, "Synced")
                # Exit loop once the file is found
                break


class Tooltip:
    """
        A class to create tooltips for Tkinter widgets. Which are small pop-ups
        that display additional information when the user hovers over a widget.

        Attributes:
            widget: The Tkinter widget to which the tooltip is attached.
            text (str): The text to display in the tooltip.
            tooltip: The Toplevel widget used to display the tooltip.
    """

    def __init__(self, widget, text):
        """
            Initializes the Tooltip object and binds events to the widget.

            Args:
                widget: The Tkinter widget to attach the tooltip to.
                text (str): The text to display in the tooltip.
        """

        # The widget this tooltip is attached to
        self.widget = widget

        # The text to display in the tooltip
        self.text = text

        # Reference to the Toplevel widget for the tooltip
        self.tooltip = None

        # Bind mouse events to the widget to show and hide the tooltip
        self.widget.bind("<Enter>", self.show_tooltip)  # Mouse enters widget
        self.widget.bind("<Leave>", self.hide_tooltip)  # Mouse leaves widget

    def show_tooltip(self, event=None):
        """
            Displays the tooltip near the widget when the mouse enters.
        """
        # Get the widget's current position and dimensions
        x, y, _, _ = self.widget.bbox("insert")  # Get the bounding box for the widget's insertion cursor
        x += self.widget.winfo_rootx() + 25  # Calculate the X coordinate relative to the screen
        y += self.widget.winfo_rooty() + 25  # Calculate the Y coordinate relative to the screen

        # Create a Toplevel widget for the tooltip
        self.tooltip = tk.Toplevel(self.widget)  # Create a new window as a child of the widget
        self.tooltip.wm_overrideredirect(True)  # Remove the window decorations (no title bar or borders)
        self.tooltip.wm_geometry(f"+{x}+{y}")  # Position the tooltip near the widget

        # Add a Label widget to display the tooltip text
        label = tk.Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1)
        # Pack the label into the Toplevel widget
        label.pack()

    def hide_tooltip(self, event=None):
        """
            Hides the tooltip when the mouse leaves the widget.
        """
        # Check if the tooltip exists
        if self.tooltip:
            # Destroy the Toplevel widget
            self.tooltip.destroy()
            # Reset the tooltip reference
            self.tooltip = None


class ProgressDialog:
    """
      A class to create and manage a progress dialog window for syncing files.
      This dialog includes a progress bar and status label.
    """

    def __init__(self, parent):
        """
            Initializes the progress dialog as a modal window.

            Args:
                parent: The parent Tkinter window or widget.
        """
        # Create a new Toplevel window as a child of the parent
        self.top = tk.Toplevel(parent)
        # Set the window title
        self.top.title("Syncing Files")
        # Set the initial size of the dialog
        self.top.geometry("300x150")
        # Make the dialog appear on top of the parent window
        self.top.transient(parent)
        # Make the dialog modal (blocks interaction with the parent)
        self.top.grab_set()

        # Center the dialog on the screen
        self.top.update_idletasks()  # Update the window's geometry and layout information
        width = self.top.winfo_width()  # Get the width of the dialog
        height = self.top.winfo_height()  # Get the height of the dialog
        x = (self.top.winfo_screenwidth() // 2) - (width // 2)  # Calculate horizontal center
        y = (self.top.winfo_screenheight() // 2) - (height // 2)  # Calculate vertical center
        self.top.geometry(f'+{x}+{y}')  # Position the dialog at the calculated coordinates

        # Add a label to display the syncing message
        self.label = ttk.Label(self.top, text="Syncing files with server...")
        # Add padding around the label
        self.label.pack(pady=10)

        # Add a progress bar to indicate syncing progress
        self.progress = ttk.Progressbar(self.top, mode='indeterminate')  # Indeterminate mode for continuous animation
        self.progress.pack(pady=10, padx=20, fill=tk.X)  # Fill horizontally with padding

        # Add a status label for detailed updates
        self.status_label = ttk.Label(self.top, text="")  # Indeterminate mode for continuous animation
        self.status_label.pack(pady=5)  # Fill horizontally with padding

        # Start the progress bar animation
        self.progress.start(10)  # Set the interval for the indeterminate animation

    def update_status(self, text):
        """
            Updates the status label with a custom message.

            Args:
                text (str): The text to display in the status label.
        """

        # Update the label's text dynamically
        self.status_label.config(text=text)

    def close(self):
        """
            Stops the progress bar animation and closes the dialog.
        """
        # Stop the indeterminate animation
        self.progress.stop()
        # Destroy the Toplevel window
        self.top.destroy()


class DropboxGUI(TkinterDnD.Tk):
    """
        A GUI application for managing file synchronization between the local client and the server.
        Provides file management functionality, real-time sync, and an intuitive interface.
    """

    def __init__(self, client, username, login_screen):
        """
            Initializes the DropboxGUI class and sets up the main components of the GUI.

            Args:
                client: The client object used for server communication.
                username: The username of the logged-in user.
                login_screen: Reference to the login screen window.
        """
        # Initialize the TkinterDnD.Tk base class
        super().__init__()

        # Set the title of the window
        self.title("Dropbox - File Sync")
        # Define the window dimensions
        self.geometry("1200x600")
        # Set background color
        self.configure(bg="#f7f9fb")
        # Store the client object
        self.client = client
        # Store the username of the logged-in user
        self.username = username
        # Reference to the login screen for navigation
        self.login_screen = login_screen

        # Handle Ctrl+C interrupt gracefully
        signal.signal(signal.SIGINT, self.handle_interrupt)

        # Set the base path dynamically based on the username
        self.base_path = os.path.join("C:/Temp", f"client_folder_{username}")

        # Ensure the base folder exists
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)

        # Initialize file system event handler as None
        self.event_handler = None
        # Initialize observer for file system changes
        self.watcher = None
        # Sync status flag to prevent multiple syncs
        self.is_syncing = False
        # Cache for file and folder icons
        self.icon_cache = {}
        # Stores references to toolbar icons for reuse.
        self.toolbar_icons = {}

        self.search_entry = None
        self.file_tree = None
        self.details_panel = None
        self.details_labels = None
        self.status_label = None
        self.sync_status = None
        self.icons = None
        self.progress_dialog = None

        # Initialize the GUI components
        self.create_menu()  # Top menu bar
        self.create_toolbar()  # Toolbar with buttons and icons
        self.create_main_content()  # Main content area (file tree and details panel)
        self.create_status_bar()  # Status bar at the bottom
        self.load_icons()  # Load icons for file types and folders

        # Disable interactive GUI elements until the sync is complete
        self.disable_gui()


        # Handle online and offline modes
        if isinstance(self.client, OfflineClient):
            print("[INFO] Offline mode: Skipping folder fetch from server.")
            # Simulate immediate setup completion
            self.after(0, self.setup_complete)

        else:
            # Fetch the user folder from the server in a separate thread
            sync_thread = threading.Thread(target=self.fetch_user_folder_from_server)
            sync_thread.start()

    def handle_interrupt(self, _args, _kwargs):
        """
            Handle SIGINT (Ctrl+C) for graceful shutdown.
        """
        print("\n[INFO] Keyboard interrupt received, performing cleanup...")
        # Trigger cleanup and close the application
        self.on_close()
        # Exit the program
        sys.exit(0)

    @staticmethod
    def make_writable_and_visible(path):
        """
            Ensure the specified path and its contents are writable and not hidden.

            Args:
                path (str): The path to a file or directory.
        """
        import stat
        if os.path.isfile(path):
            # Make the file writable
            os.chmod(path, stat.S_IWRITE)
            # Remove hidden attribute (Windows-specific)
            os.system(f'attrib -h "{path}"')
        elif os.path.isdir(path):
            # Make the directory writable
            os.chmod(path, stat.S_IWRITE)
            # Remove hidden attribute (Windows-specific)
            os.system(f'attrib -h "{path}"')

            # Recursively ensure contents are writable and visible
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    os.chmod(file_path, stat.S_IWRITE)
                    os.system(f'attrib -h "{file_path}"')
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    os.chmod(dir_path, stat.S_IWRITE)
                    os.system(f'attrib -h "{dir_path}"')

    def disable_gui(self):
        """
            Disables all interactive GUI elements to prevent user actions during sync.
        """

        # Iterate through all child widgets
        for child in self.winfo_children():
            # Check for interactive widgets
            if isinstance(child, (tk.Button, ttk.Button, tk.Entry, ttk.Entry)):
                # Disable the widget
                child.configure(state='disabled')

        # Disable file tree selection
        self.file_tree.configure(selectmode='none')

    def setup_complete(self):
        """
            Re-enables the GUI and starts folder monitoring after sync setup is complete.
        """

        # Re-enable all GUI elements
        self.enable_gui()

        # Ensure the folder exists
        if os.path.exists(self.base_path):
            # Start monitoring the folder for changes
            self.start_watching(self.base_path)

        # Load the initial files from the folder into the GUI
        self.load_initial_files()

    def fetch_user_folder_from_server(self):
        """
           Synchronizes the user folder with the server by downloading files to the local folder.
        """
        try:

            self.make_writable_and_visible(self.base_path)
            # Delete the local folder if it exists
            if os.path.exists(self.base_path):
                shutil.rmtree(self.base_path)

                print(f"[INFO] Deleted local folder: {self.base_path}")

            # Request the user folder from the server
            self.client.client_socket.send("GET_USER_FOLDER".encode())

            # Process server response to download all files
            while True:
                # Receive and decode server response
                response = self.client.client_socket.recv(1024).decode().strip()

                if response == "END_OF_FOLDER":  # Check for end of folder sync
                    # End of sync process
                    print("End of folder sync.")
                    break
                elif response == "SYNC":  # Control message indicating sync start
                    # This is a control message to signal the start of syncing
                    print("Sync message received. Proceeding to file transfer.")
                    continue  # Ignore SYNC control message
                elif response.startswith("FILE"):  # File transfer command
                    # Split the response to extract file details
                    file_info = response.split(',')
                    if len(file_info) != 2:
                        print(f"Unexpected server response: {response}")
                        continue

                    # Extract relative path (remove " FILE ")
                    relative_path = file_info[0][5:]  # Remove "FILE " prefix to get the relative path
                    file_size = int(file_info[1])

                    # Notify the server that the client is ready to receive
                    self.client.client_socket.send("READY".encode())

                    # Determine local file path and ensure its directories exist
                    local_file_path = os.path.join(self.base_path, relative_path)
                    os.makedirs(os.path.dirname(local_file_path), exist_ok=True)

                    # Receive the file and save it locally
                    with open(local_file_path, 'wb') as file:
                        bytes_received = 0
                        while bytes_received < file_size:
                            # Read data in chunks
                            chunk = self.client.client_socket.recv(min(4096, file_size - bytes_received))

                            # Check for end of file
                            if chunk == b"EOF":
                                # Stop when we receive EOF
                                print(f"EOF received for {relative_path}")
                                break

                            # Write the chunk to the file
                            file.write(chunk)
                            bytes_received += len(chunk)

                    # Acknowledge the server after receiving the file
                    self.client.client_socket.send(b"ACK")


                    if os.path.exists(local_file_path):
                        # Mark the file as "Synced" when it is downloaded from the server
                        self.add_file_to_tree(local_file_path, status="Synced")
                    else:
                        print(f"[WARNING] File {local_file_path} does not exist locally but was attempted to add.")


                # Final server acknowledgment
                elif response == "DONE":
                    # Final acknowledgment to the server
                    self.client.client_socket.send(b"ACK")
                    print("All files have been synchronized.")
                    break
                else:
                    # Handle unexpected responses
                    print(f"Unexpected server response: {response}")
                    continue

        except Exception as error_name:
            print(f"[ERROR] Failed to download folder: {error_name}")

            if self.winfo_exists():
                messagebox.showerror("Download Error", f"Error during download: {error_name}")

        finally:
            # After downloading the folder, enable the GUI and start monitoring the folder
            self.after(0, self.setup_complete)


    def enable_gui(self):
        """
            Re-enable all interactive GUI elements after synchronization.
        """

        # Iterate through all child widgets
        for child in self.winfo_children():
            # Check for interactive widgets
            if isinstance(child, (tk.Button, ttk.Button, tk.Entry, ttk.Entry)):
                # Enable the widget
                child.configure(state='normal')

        # Enable file tree selection
        self.file_tree.configure(selectmode='browse')

    def create_menu(self):
        """
            Create the menu bar with File and Edit menus, and attach their respective commands.
        """

        # Create the menu bar
        menubar = tk.Menu(self)

        # Attach the menu bar to the window
        self.config(menu=menubar)

        # File menu and its commands
        file_menu = tk.Menu(menubar, tearoff=0)  # Create the File menu
        menubar.add_cascade(label="File", menu=file_menu)  # Add File menu to the menu bar
        file_menu.add_command(label="New File", command=self.prompt_create_file)  # Command to create a new file
        file_menu.add_command(label="Import", command=self.import_file)  # Command to import files/folders
        file_menu.add_command(label="Open", command=self.open_file)  # Command to open a file
        file_menu.add_separator()  # Add a separator
        file_menu.add_command(label="Logout", command=self.quit)  # Command to log out
        file_menu.add_command(label="Delete user", command=self.delete_user)  # Command to delete the user
        file_menu.add_command(label="Exit", command=self.exit)  # Command to exit the application

        # Edit menu and its commands
        edit_menu = tk.Menu(menubar, tearoff=0)  # Create the Edit menu
        menubar.add_cascade(label="Edit", menu=edit_menu)  # Add Edit menu to the menu bar
        edit_menu.add_command(label="Rename", command=self.rename_file)  # Command to rename a file
        edit_menu.add_command(label="Delete", command=self.delete_file)  # Command to delete a file

    def create_toolbar(self):
        """
            Create the toolbar with buttons for common actions, and add tooltips to each button.
        """
        # Create a toolbar frame
        toolbar = tk.Frame(self, bg="#e1e8ed")

        # Place it at the top and make it stretch horizontally
        toolbar.pack(side="top", fill="x")

        # Dictionary of toolbar icons and their corresponding file paths
        self.toolbar_icons["new_file"] = self.load_icon(os.path.join(icons_folder_path, "new_file_icon.png")),
        self.toolbar_icons["import"] = self.load_icon(os.path.join(icons_folder_path, "import_icon.png"))
        self.toolbar_icons["rename"] = self.load_icon(os.path.join(icons_folder_path, "rename_icon.png"))
        self.toolbar_icons["open"] = self.load_icon(os.path.join(icons_folder_path, "open_icon.png"))
        self.toolbar_icons["delete"] = self.load_icon(os.path.join(icons_folder_path, "delete_icon.png"))
        self.toolbar_icons["update"] = self.load_icon(os.path.join(icons_folder_path, "update_icon.png"))
        self.toolbar_icons["download"] = self.load_icon(os.path.join(icons_folder_path, "download_icon.png"))
        self.toolbar_icons["info"] = self.load_icon(os.path.join(icons_folder_path, "info_icon.png"))

        # Tooltips for each toolbar button
        tooltip_texts = {
            "new_file": "Create a new file",
            "import": "Import a file or folder",
            "rename": "Rename selected item",
            "open": "Open selected item",
            "delete": "Delete selected item",
            "update": "Update files with server",
            "download": "Download files from server",
            "info": "Information about the app"
        }

        # Create buttons for each icon and attach the appropriate command
        for icon_name, icon_image in self.toolbar_icons.items():
            button = tk.Button(toolbar, image=cast('_Image | str', icon_image),
                               command=getattr(self, f"{icon_name}_action", None))
            # Arrange buttons horizontally with padding
            button.pack(side="left", padx=2, pady=2)
            # Add tooltip to the button
            Tooltip(button, tooltip_texts[icon_name])

        # Add a search bar to the toolbar
        search_frame = tk.Frame(toolbar, bg="#e1e8ed")  # Create a frame for the search bar
        search_frame.pack(side="right", padx=5, pady=5)  # Position it on the right side
        self.search_entry = tk.Entry(search_frame, width=30)  # Create an entry field for search input
        self.search_entry.pack(side="left")  # Pack it inside the search frame
        search_button = tk.Button(search_frame, text="Search", command=self.search_files)  # Search button
        search_button.pack(side="left", padx=5)  # Add padding around the button
        Tooltip(search_button, "Search for files")  # Add tooltip for the search button

    # Action methods for toolbar buttons
    def new_file_action(self):
        # Trigger the new file creation process
        self.prompt_create_file()

    def import_action(self):
        # Trigger the import file/folder process
        self.import_file()

    def rename_action(self):
        # Trigger the rename process
        self.rename_file()

    def open_action(self):
        # Trigger the open file process
        self.open_file()

    def delete_action(self):
        # Trigger the delete file process
        self.delete_file()

    def update_action(self):
        # Trigger the synchronization process
        self.update_files()

    def download_action(self):
        # Fetch the user folder from the server in a separate thread
        self.download_files()

    def info_action(self):
        # Display information about the application
        self.info_app()

    def create_main_content(self):
        """
            Create the main content area of the GUI, including the file tree view and details panel.
        """
        # Create a horizontal paned window
        paned_window = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        # Allow it to expand and fill the space
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create left and right frames for the file tree and details panel
        left_frame = ttk.Frame(paned_window)
        right_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=3)  # Add the left frame with higher weight
        paned_window.add(right_frame, weight=1)  # Add the right frame with lower weight

        # Create the file tree view
        self.file_tree = ttk.Treeview(left_frame, columns=("Name", "Status", "Modified", "Path"), show="tree headings")
        self.file_tree.heading("#0", text="")  # Empty heading for the first column
        self.file_tree.heading("Name", text="Files")  # Name column
        self.file_tree.heading("Status", text="Status")  # Status column
        self.file_tree.heading("Modified", text="Modified")  # Modified column
        self.file_tree.heading("Path", text="File Path")  # File path column

        # Configure column settings
        self.file_tree.column("#0", width=40, stretch=tk.NO)  # Fixed width for the first column
        self.file_tree.column("Name", width=200, anchor=tk.W)  # Left-align the Name column
        self.file_tree.column("Status", width=100, anchor=tk.CENTER)  # Center-align the Status column
        self.file_tree.column("Modified", width=150, anchor=tk.CENTER)  # Center-align the Modified column
        self.file_tree.column("Path", width=300, anchor=tk.W)  # Left-align the Path column
        self.file_tree.pack(fill=tk.BOTH, expand=True)  # Fill the available space

        # Drag and drop registration for the file tree
        self.file_tree.drop_target_register(DND_FILES)  # type: ignore
        self.file_tree.dnd_bind('<<Drop>>', self.on_file_drop)  # type: ignore

        # Right-click context menu
        self.file_tree.bind("<Button-3>", self.show_context_menu)

        # Details Panel on the right-hand side
        self.details_panel = ttk.LabelFrame(right_frame, text="File Details")
        self.details_panel.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add labels for file details
        self.details_labels = {
            "Name": ttk.Label(self.details_panel, text="Name: "),
            "Type": ttk.Label(self.details_panel, text="Type: "),
            "Size": ttk.Label(self.details_panel, text="Size: "),
            "Modified": ttk.Label(self.details_panel, text="Modified: "),
            "Path": ttk.Label(self.details_panel, text="Path: "),
        }

        # Pack labels into the details panel
        for label in self.details_labels.values():
            label.pack(anchor="w", padx=5, pady=2)

        # Bind selection event to update the details panel when a file is selected
        self.file_tree.bind("<<TreeviewSelect>>", self.update_details_panel)

    def create_status_bar(self):
        """
            Create the status bar at the bottom of the window to display app status and sync status.
        """
        status_bar = tk.Frame(self, relief=tk.SUNKEN, bd=1)  # Create a sunken frame for the status bar
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)  # Position it at the bottom

        self.status_label = tk.Label(status_bar, text="Ready", anchor=tk.W)  # Status label on the left
        self.status_label.pack(side=tk.LEFT, padx=5)  # Add padding to the left side

        self.sync_status = tk.Label(status_bar, text="Connected", anchor=tk.E, fg="green")  # Sync status on the right
        self.sync_status.pack(side=tk.RIGHT, padx=5)  # Add padding to the right side

    def load_icons(self):
        """
           Load file type icons for different file formats into a dictionary.
        """

        # Mapping of file types/extensions to their respective icons
        self.icons = {
            "folder": self.load_icon(os.path.join(icons_folder_path, "folder_icon.png")),
            "file": self.load_icon(os.path.join(icons_folder_path, "file_icon.png")),
            "txt": self.load_icon(os.path.join(icons_folder_path, "txt_icon.png")),
            "pdf": self.load_icon(os.path.join(icons_folder_path, "pdf_icon.png")),
            "jpg": self.load_icon(os.path.join(icons_folder_path, "image_icon.png")),
            "png": self.load_icon(os.path.join(icons_folder_path, "image_icon.png")),
            "docx": self.load_icon(os.path.join(icons_folder_path, "word_icon.png")),
            "xlsx": self.load_icon(os.path.join(icons_folder_path, "excel_icon.png")),
            "pptx": self.load_icon(os.path.join(icons_folder_path, "powerpoint_icon.png")),
        }

    def load_icon(self, path):
        """
            Load an icon from the given file path and cache it.

            Args:
                path (str): Path to the icon file.

            Returns:
                ImageTk.PhotoImage: The loaded and resized icon.
        """

        # Check if the icon is already cached
        if path not in self.icon_cache:
            # Open the icon image
            image = Image.open(path)
            # Resize the icon to 20x20 pixels
            image = image.resize((20, 20), Image.Resampling.LANCZOS)
            # Cache the resized icon
            self.icon_cache[path] = ImageTk.PhotoImage(image)

        # Return the cached icon
        return self.icon_cache[path]

    def get_file_icon(self, file_path):
        """
            Determine the appropriate icon for a file based on its type or extension.

            Args:
                file_path (str): The path of the file.

            Returns:
                ImageTk.PhotoImage: The corresponding icon for the file.
        """

        # Check if the path points to a folder
        if os.path.isdir(file_path):
            # Return the folder icon
            return self.icons["folder"]

        # Extract the file extension (lowercase)
        ext = os.path.splitext(file_path)[1].lower()[1:]

        # Return the icon for the extension or a default file icon
        return self.icons.get(ext, self.icons["file"])

    def show_context_menu(self, event):
        """
            Display a context menu (right-click menu) for file tree actions.

            Args:
                event: The mouse event triggering the menu.
        """

        # Identify the tree item under the cursor
        item = self.file_tree.identify_row(event.y)

        # If an item is clicked
        if item:
            self.file_tree.selection_set(item)  # Select the clicked item
            context_menu = tk.Menu(self, tearoff=0)  # Create a context menu
            context_menu.add_command(label="Open", command=self.open_file)  # Option to open the file
            context_menu.add_command(label="Rename", command=self.rename_file)  # Option to rename the file
            context_menu.add_command(label="Delete", command=self.delete_file)  # Option to delete the file
            context_menu.tk_popup(event.x_root, event.y_root)  # Show the menu at the cursor position

    def update_details_panel(self, _args):
        """
            Update the details panel with information about the selected file.
        """

        # Get the selected item in the file tree
        selected_item = self.file_tree.selection()

        # If an item is selected
        if selected_item:
            file_path = self.file_tree.item(selected_item, "values")[3]  # Get the file path from the item
            self.preview_file(file_path)  # Show file preview when file is selected

    @staticmethod
    def get_size_format(b, factor=1024, suffix="B"):
        """
           Format a file size into human-readable format (e.g., KB, MB).

           Args:
               b (int): The file size in bytes.
               factor (int): The unit conversion factor, default is 1024.
               suffix (str): The suffix to append to the size, default is "B".

           Returns:
               str: The formatted file size string.
        """

        # Iterate through size units
        for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
            # If the size is less than the factor
            if b < factor:
                # Return the formatted size
                return f"{b:.2f}{unit}{suffix}"

            # Convert to the next unit
            b /= factor

        # Handle very large sizes
        return f"{b:.2f}Y{suffix}"

    def search_files(self):
        """
            Search for files in the file tree based on a query in the search entry.
        """

        # Get the search query and convert to lowercase
        query = self.search_entry.get().lower()

        # Iterate through all items in the file tree
        for item in self.file_tree.get_children():
            # Get the file name and convert to lowercase
            file_name = self.file_tree.item(item, "values")[0].lower()

            # Check if the query is in the file name
            if query in file_name:
                # Select the matching item
                self.file_tree.selection_set(item)
                # Set focus to the item
                self.file_tree.focus(item)
                # Ensure the item is visible
                self.file_tree.see(item)
                # Stop after the first match
                break

    def update_files(self):
        """
        Deletes all content in the user's folder on the server and uploads the current state of the local folder.
        """
        time.sleep(1)
        if self.is_syncing:
            return  # Prevent multiple sync processes from running simultaneously

        self.is_syncing = True

        # Initialize event handler if not already initialized
        if self.event_handler is None:
            self.event_handler = FileEventHandler(self.file_tree)

        self.event_handler.is_gui_action = True  # Indicate this is a GUI action

        # Ensure event handler is initialized
        if self.event_handler is None:
            messagebox.showerror("Error", "File event handler is not initialized.")
            self.is_syncing = False
            return

        self.event_handler.is_gui_action = True  # Indicate this is a GUI action

        # Stop the file system watcher temporarily
        if self.watcher:
            self.watcher.stop()

        # Show a progress dialog and disable the GUI
        self.progress_dialog = ProgressDialog(self)
        self.disable_gui()

        # Start the update process in a separate thread
        update_thread = threading.Thread(target=self._perform_update)
        update_thread.start()

    def _perform_update(self):
        """
        Perform the update process: delete all server folder content and upload local folder content.
        """
        # Introduction a slight delay before starting the process
        time.sleep(1)
        try:
            if self.progress_dialog and self.progress_dialog.top.winfo_exists():
                self.progress_dialog.update_status("Deleting all files on server...")

            # Step 1: Send a command to delete all server files
            self.client.client_socket.send("DELETE_ALL".encode())
            response = self.client.client_socket.recv(1024).decode().strip()
            if response != "ACK":
                raise Exception("Failed to delete all files on the server.")

            # Step 2: Upload all files from the local folder
            if self.progress_dialog and self.progress_dialog.top.winfo_exists():
                self.progress_dialog.update_status("Uploading files to server...")

            local_files = os.listdir(self.base_path)
            for file_name in local_files:
                file_path = os.path.join(self.base_path, file_name)
                rel_path = os.path.relpath(file_path, self.base_path)

                if self.progress_dialog and self.progress_dialog.top.winfo_exists():
                    self.progress_dialog.update_status(f"Uploading: {rel_path}")

                # Recursively send folders and files
                self.client.send_file(file_path)

                # Mark the file as synced after upload
                self.event_handler.mark_as_synced(file_path)
        except Exception as error_name:
            if self.winfo_exists():
                messagebox.showerror("Update Error", f"Error during update: {str(error_name)}")
        finally:
            self.after(0, self._finish_sync)

    def download_files(self):
        """
        Deletes the local folder and downloads the content of the user folder from the server.
        """
        time.sleep(1)
        if self.is_syncing:
            return  # Prevent multiple sync processes from running simultaneously

        self.is_syncing = True
        self.event_handler.is_gui_action = True  # Indicate this is a GUI action


        # Stop the file system watcher temporarily
        if self.watcher:
            self.watcher.stop()

        # Show a progress dialog and disable the GUI
        self.progress_dialog = ProgressDialog(self)
        self.disable_gui()

        # Start the download process in a separate thread
        download_thread = threading.Thread(target=self._perform_download)
        download_thread.start()

    def _perform_download(self):
        """
        Perform the download process: delete the local folder and download the server content.
        """        
        # Introduction a slight delay before starting the process
        time.sleep(1)
        try:
            if self.progress_dialog and self.progress_dialog.top.winfo_exists():
                self.progress_dialog.update_status("Deleting local folder...")

            # Step 1: Remove any read-only or hidden attributes before deleting
            if os.path.exists(self.base_path):
                self.remove_folder_attributes(self.base_path)  # Ensure folder is writable and visible
                shutil.rmtree(self.base_path)

            # Step 2: Download the server folder
            if self.progress_dialog and self.progress_dialog.top.winfo_exists():
                self.progress_dialog.update_status("Downloading files from server...")

            # Use the fetch_user_folder_from_server helper method
            self.fetch_user_folder_from_server()

        except Exception as error_name:
            if self.winfo_exists():
                messagebox.showerror("Download Error", f"Error during download: {str(error_name)}")
        finally:
            self.after(0, self._finish_sync)

    @staticmethod
    def remove_folder_attributes(path):
        """
        Removes the read-only and hidden attributes from the specified folder and its contents.

        Args:
            path (str): Path to the folder whose attributes need adjustment.
        """
        if platform.system() == "Windows":
            try:
                # Use Windows-specific commands to remove hidden and read-only attributes
                subprocess.call(f'attrib -h -r "{path}" /S /D', shell=True)
            except Exception as error_name:
                print(f"[ERROR] Failed to update folder attributes for '{path}': {error_name}")
        else:
            # On Linux or Mac, ensure writable permissions
            for root, dirs, files in os.walk(path):
                for file in files:
                    os.chmod(os.path.join(root, file), stat.S_IWRITE)
                for dir_name in dirs:
                    os.chmod(os.path.join(root, dir_name), stat.S_IWRITE)

    def _finish_sync(self):
        """
        Finalize the update or download process by re-enabling the GUI and restarting file watchers.
        """
        if hasattr(self, 'progress_dialog') and self.progress_dialog.top.winfo_exists():
            self.progress_dialog.close()

        if self.winfo_exists():
            self.enable_gui()

        if os.path.exists(self.base_path):
            self.start_watching(self.base_path)

        # Update file statuses to "Synced" after successful operations
        for item in self.file_tree.get_children():
            file_path = self.file_tree.item(item, "values")[3]
            self.event_handler.mark_as_synced(file_path)

        if self.status_label.winfo_exists() and self.sync_status.winfo_exists():
            self.status_label.config(text="Operation completed")
            self.sync_status.config(text="Connected", fg="green")

        self.is_syncing = False
        self.event_handler.is_gui_action = False

    def delete_files_on_server(self, files_to_delete):
        """
            Delete specified files from the server.

            Args:
                files_to_delete (set): A set of file names to delete from the server.
        """

        # Iterate through files marked for deletion
        for file_name in files_to_delete:
            self.client.client_socket.send(f"DELETE_FILE,{file_name}".encode())  # Send delete command to the server

            # Handle the response from the server
            response = self.client.client_socket.recv(1024).decode().strip()
            # Check if the deletion was acknowledged
            if response != "ACK":
                print(f"Failed to delete file {file_name} on server.")

    def fetch_server_file_list(self):
        """
            Fetch the list of files available on the server.

            Returns:
                set: A set of file names present on the server.
        """
        # Send a request to the server to get the current list of files
        self.client.client_socket.send("LIST_FILES".encode())
        response = self.client.client_socket.recv(4096).decode().strip()

        # Parse the response into a set
        if response == 'END_OF_FOLDER':
            return {}

        server_files = set(response.split(',')) if response else set()
        return server_files

    @staticmethod
    def info_app():
        """
            Open the project portfolio document or show an error if not found.
        """
        # Path to the document
        file_path = os.path.join(os.getcwd(), "Project Portfolio.docx")

        # Check if the document exists
        if os.path.exists(file_path):
            try:
                # Attempt to open the file
                os.startfile(file_path)
            except Exception as error_name:
                # Handle any errors during the process
                messagebox.showerror("Error", f"Could not open document: {error_name}")
        else:
            messagebox.showerror("File Not Found", "The document 'project portfolio.docx' was not found.")

    def add_file_to_tree(self, file_path, status="Not Synced"):
        """
        Add a file or folder to the file tree view.

        Args:
            file_path (str): The full path of the file or folder to add.
            status (str): The sync status of the file (default: "Not Synced").
        """
        # Extract the file name from the path
        file_name = os.path.basename(file_path)
        # Get the last modified time
        modified_time = os.path.getmtime(file_path)
        # Convert the modified time to a readable string
        modified_time_str = time.ctime(modified_time)
        # Get the appropriate icon for the file type
        icon = self.get_file_icon(file_path)

        # Check if the file is already in the tree, and add it if not
        if file_path not in [self.file_tree.item(item, "values")[3] for item in self.file_tree.get_children()]:
            self.file_tree.insert("", tk.END, values=(file_name, status, modified_time_str, file_path), image=icon)

        # Update the status label to indicate the file was added
        self.status_label.config(text=f"Added: {file_name}")

    def load_initial_files(self):
        """
            Load all files and folders from the base path into the file tree.

            Ensures the base path exists and applies platform-specific settings to hide the folder.
        """

        # Ensure the base path exists
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)

        if platform.system() == "Windows":
            # Set the folder as read-only and hidden on Windows
            try:
                os.chmod(self.base_path, stat.S_IREAD)  # Make it read-only
                os.system(f'attrib +h "{self.base_path}"')  # Mark it as hidden
            except Exception as error_name:
                print(f"Error setting hidden attribute for {self.base_path} on Windows: {error_name}")

        elif platform.system() == "Linux":
            # Rename the folder to start with a '.' to hide it on Linux
            hidden_path = os.path.join(os.path.dirname(self.base_path), f".{os.path.basename(self.base_path)}")
            try:
                if not os.path.exists(hidden_path):
                    os.rename(self.base_path, hidden_path)  # Rename to hide
                    self.base_path = hidden_path  # Update the base path reference
            except Exception as error_name:
                print(f"Error hiding folder on Linux: {error_name}")

        # Iterate through the base path and add all files and folders to the tree
        for root, _, files in os.walk(self.base_path):
            for file in files:
                self.add_file_to_tree(os.path.join(root, file))
            for folder in _:
                self.add_file_to_tree(os.path.join(root, folder))


    def delete_file(self):
        """
            Delete the selected file or folder from the base path and the file tree.

            Handles both files and directories, updating the GUI accordingly.
        """
        # Get the selected item in the tree
        selected_item = self.file_tree.selection()

        if selected_item:
            # Get the full path of the selected item
            file_path = self.file_tree.item(selected_item, "values")[3]
            # Mark the action as initiated by the GUI
            self.event_handler.is_gui_action = True
            if os.path.isdir(file_path):
                # Delete a directory and its contents
                try:
                    # Remove the directory and its contents
                    shutil.rmtree(file_path)
                    # Remove the item from the GUI
                    self.file_tree.delete(selected_item)
                except Exception as error_name:
                    messagebox.showerror("Error", f"Error deleting folder: {str(error_name)}")
            else:
                # Delete a file
                try:
                    # Remove the file
                    os.remove(file_path)
                    # Remove the item from the GUI
                    self.file_tree.delete(selected_item)
                except Exception as error_name:
                    messagebox.showerror("Error", f"Error deleting file: {str(error_name)}")

            # Reset the GUI action flag
            self.event_handler.is_gui_action = False

    def preview_file(self, file_path):
        """
            Display a preview of the selected file in the details panel.

            Supports images, text files, and PDFs. For unsupported formats, shows a message.
        """
        # Clear previous preview if any
        for widget in self.details_panel.winfo_children():
            widget.destroy()

        # Get the file extension
        file_extension = os.path.splitext(file_path)[1].lower()

        if file_extension in [".jpg", ".jpeg", ".png", ".gif", ".bmp"]:
            # Load and display an image file
            try:
                # Load and resize the image for preview
                image = Image.open(file_path)  # Open the image
                image.thumbnail((200, 200), Image.Resampling.LANCZOS)  # Resize the image for display
                photo = ImageTk.PhotoImage(image)

                # Display the image in the details panel
                image_label = ttk.Label(self.details_panel, image=photo)
                image_label.image = photo  # Keep a reference to avoid garbage collection
                image_label.pack(pady=10)
            except Exception as error_name:
                print(f"Error loading image preview: {error_name}")

        elif file_extension in [".txt", ".log", ".md"]:
            # Display the first few lines of a text file
            try:
                # Display the first few lines of a text file
                with open(file_path, "r", encoding="utf-8") as file:
                    content = file.read(200)  # Read first 200 characters for preview

                # Add the text content to the details panel
                text_preview = tk.Text(self.details_panel, wrap=tk.WORD, height=10, width=30)
                text_preview.insert(tk.END, content)
                text_preview.configure(state="disabled")  # Make it read-only
                text_preview.pack(pady=10)
            except Exception as error_name:
                print(f"Error loading text preview: {error_name}")
        elif file_extension == ".pdf":
            pdf_document = None
            # Display the first page of a PDF file as an image
            try:
                # Load the first page of the PDF as an image
                pdf_document = fitz.open(file_path)  # Open the PDF document

                first_page = pdf_document[0]  # Get the first page
                pix = fitz.Pixmap(first_page)  # Render the page as a pixmap
                image = Image.frombytes("RGB", (pix.width(), pix.height()), pix.samples)

                # Resize the PDF preview for display
                image.thumbnail((250, 250), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(image)

                # Display the image in the details panel
                image_label = ttk.Label(self.details_panel, image=photo)
                image_label.image = photo  # Keep a reference to avoid garbage collection
                image_label.pack(pady=10)
            except Exception as error_name:
                print(f"Error loading PDF preview: {error_name}")
            finally:
                pdf_document.close()
        else:
            # Display a message for unsupported file types
            ttk.Label(self.details_panel, text="Preview not available for this file type").pack(pady=10)

        # Update the details panel with basic file information
        self.update_details_panel_from_path(file_path)

    def update_details_panel_from_path(self, file_path):
        """
            Updates the details panel with information about the specified file or folder.

            Args:
                file_path (str): The path to the file or folder to display.
        """
        # Retrieve file metadata like size, modification time, etc.
        file_stats = os.stat(file_path)
        # Determine if it's a folder or file.
        file_type = "Folder" if os.path.isdir(file_path) else "File"
        # Format the size into human-readable form.
        file_size = self.get_size_format(file_stats.st_size)

        # Display the file's name, type, size, modification time, and path in the details panel.
        ttk.Label(self.details_panel, text=f"Name: {os.path.basename(file_path)}").pack(anchor="w")
        ttk.Label(self.details_panel, text=f"Type: {file_type}").pack(anchor="w")
        ttk.Label(self.details_panel, text=f"Size: {file_size}").pack(anchor="w")
        ttk.Label(self.details_panel, text=f"Modified: {time.ctime(file_stats.st_mtime)}").pack(anchor="w")
        ttk.Label(self.details_panel, text=f"Path: {file_path}").pack(anchor="w")

    def rename_file(self):
        """
            Renames the selected file or folder in the file tree.
            Prompts the user for a new name and updates both the file system and GUI.
        """
        # Get the selected item in the file tree.
        selected_item = self.file_tree.selection()

        # If no item is selected, show a warning.
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a file to rename.")
            return

        # Get the current file name.
        current_name = self.file_tree.item(selected_item, "values")[0]
        # Get the current file path.
        file_path = self.file_tree.item(selected_item, "values")[3]

        # Ask the user for the new name, pre-filled with the current name.
        new_name = simpledialog.askstring("Rename File", f"Enter new name for {current_name}:",
                                          initialvalue=current_name)

        # Do nothing if the name hasn't changed.
        if not new_name or new_name == current_name:
            return

        # Generate the new file path.
        new_path = os.path.join(os.path.dirname(file_path), new_name)

        try:
            self.event_handler.is_gui_action = True  # Prevent the event handler from reacting to this change.
            os.rename(file_path, new_path)  # Rename the file in the file system.

            # Update the file tree with the new name, path, and modification time.
            self.file_tree.item(selected_item,
                                values=(new_name, "Not Synced", time.ctime(os.path.getmtime(new_path)), new_path))
            messagebox.showinfo("Success", f"{current_name} has been renamed to {new_name}.")

            # Re-enable event handler for other changes.
            self.event_handler.is_gui_action = False

        except Exception as error_name:
            # Handle any errors during renaming.
            messagebox.showerror("Error", f"Failed to rename {current_name}: {str(error_name)}")
        finally:
            self.load_initial_files()
    def prompt_create_file(self):
        """
            Prompts the user to create a new file in the base directory.
            The file is added to the file system and reflected in the GUI.
        """
        # Prompt for the file name.
        filename = simpledialog.askstring("Create File", "Enter file name:")
        if filename:
            # Construct the full path of the new file.
            file_path = os.path.join(self.base_path, filename)

            # Only proceed if the file does not already exist.
            if not os.path.exists(file_path):
                try:
                    # Prevent event handler from reacting to this change.
                    self.event_handler.is_gui_action = True

                    # Create an empty file.
                    with open(file_path, 'w') as f:
                        f.write("")

                    # Add the file to the GUI tree.
                    self.add_file_to_tree(file_path)
                    messagebox.showinfo("Success", f"{filename} has been created.")
                finally:
                    # Re-enable event handler.
                    self.event_handler.is_gui_action = False
            else:
                # Error if file exists.
                messagebox.showerror("Error", "File already exists.")


    def import_file(self):
        """
            Prompts the user to select a file for import and copies the file
            to the base directory. Adds the file to the GUI file tree.
        """
        # Prompt for file selection
        import_path = filedialog.askopenfilename()

        # Proceed only if a valid path was selected
        if import_path:
            # Ensure the selected path is a file
            if os.path.isfile(import_path):
                try:
                    if self.event_handler:  # Ensure event handler exists
                        # Temporarily disable event handling
                        self.event_handler.is_gui_action = True
                    # Copy file to base path and add it to the tree
                    shutil.copy(import_path, self.base_path)
                    # Add the new file to the file tree in the GUI
                    self.add_file_to_tree(os.path.join(self.base_path, os.path.basename(import_path)))
                    messagebox.showinfo("Success", "File imported successfully.")
                finally:
                    if self.event_handler:
                        # Re-enable event handling
                        self.event_handler.is_gui_action = False
            else:
                # Handle invalid selections
                messagebox.showerror("Error", "Invalid file or folder selected.")

    def quit(self):
        """
            Logs the user out and cleans up resources. Stops the file watcher,
            sends a logout command to the server, and deletes the local folder.
        """
        try:
            # Stop the watchdog observer if it exists
            if self.watcher:
                self.watcher.stop()
                self.watcher.join()  # Ensure observer fully stops
                self.watcher = None  # Clear reference to the observer

            # Send the logout command to the server and close the socket
            if self.client.client_socket:
                self.client.client_socket.send("LOGOUT".encode())
                self.client.client_socket.shutdown(socket.SHUT_RDWR)
                self.client.client_socket.close()
                print("Socket closed on logout.")

            # Perform additional logout-related cleanup
            login_window = tk.Toplevel()
            LoginSignupScreen(self.client)
            login_window.attributes('-topmost', True)

            # Set folder to writable and ensure it's hidden on Windows
            if platform.system() == "Windows":
                os.chmod(self.base_path, stat.S_IWRITE)  # Allow to write access
                subprocess.call(["attrib", "+h", self.base_path])  # Ensure it remains hidden

            # Attempt to delete the folder
            if os.path.exists(self.base_path):
                shutil.rmtree(self.base_path)
                print(f"Local folder '{self.base_path}' deleted successfully.")
            else:
                print(f"Folder '{self.base_path}' does not exist.")

            # Close the GUI window
            self.destroy()

        except Exception as error_name:
            # Handle any errors during logout
            print(f"Error during logout: {error_name}")

    def delete_user(self):
        """
            Prompts the user for a password to confirm account deletion.
            Initiates the deletion process in a separate thread.
        """
        password = simpledialog.askstring("Password", "Enter password to confirm deletion:", show="*")

        if password:
            # Start a separate thread to handle the user deletion process
            delete_thread = threading.Thread(target=self._perform_delete_user, args=(password,))
            delete_thread.start()
        else:
            messagebox.showwarning("Password required", "Please enter your password to delete the user.")

    def _perform_delete_user(self, password):
        """
            Handles the user deletion process by communicating with the server
            and cleaning up local data.

            Args:
                password (str): The user's password for verification.
        """
        try:
            # Step 1: Send delete request to the server
            self.client.client_socket.send("Delete_user".encode())
            server_ack = self.client.client_socket.recv(1024).decode().strip()

            # Server acknowledges the deletion request
            if server_ack == "Delete_user_ack":
                # Step 2: Send the username and password for confirmation
                self.client.client_socket.send(f"{self.username},{password}".encode())
                response = self.client.client_socket.recv(1024).decode().strip()

                if response == "Remove successful":
                    # Delete the local user folder in C:/Temp
                    local_folder_path = os.path.join("C:/Temp", f"client_folder_{self.username}")
                    if os.path.exists(local_folder_path):
                        try:
                            shutil.rmtree(local_folder_path)
                            print(f"Local folder '{local_folder_path}' deleted successfully.")
                        except Exception as error_name:
                            print(f"Failed to delete local folder '{local_folder_path}': {error_name}")

                    messagebox.showinfo("Remove User", "The user was successfully removed. Exiting..")
                    # Exit the application
                    self.quit()
                else:
                    # Inform user of failure
                    messagebox.showwarning("Deletion Failed", response)
            else:
                messagebox.showerror("Server Error", "Unexpected server response during deletion. no Delete_user_ack")

        except socket.timeout:
            # Handle server timeout
            messagebox.showerror("Server Timeout", "No response from server.")
        except Exception as error_name:
            # Handle general errors
            messagebox.showerror("Error", f"An error occurred: {error_name}")
        finally:
            # Reset the socket timeout
            self.client.client_socket.settimeout(None)

    def exit(self):
        """
            Sends an exit command to the server and closes the application.
        """
        try:
            # Notify the server of exit
            self.client.client_socket.send("fEXIT".encode())
            # Close the GUI window
            self.destroy()
        except Exception as error_name:
            # Handle errors during exit
            print(f"Error during logout: {error_name}")

    def open_file(self):
        """
            Opens the selected file using the default system application.
        """
        # Get the selected item in the file tree
        selected_item = self.file_tree.selection()

        # If no item is selected, show a warning
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a file to open.")
            return
        try:
            self.event_handler.is_gui_action = True  # Temporarily disable event handling
            file_path = self.file_tree.item(selected_item, "values")[3]  # Retrieve the file path
            os.startfile(file_path)  # Open the selected file
        finally:
            # Re-enable event handling
            self.event_handler.is_gui_action = False

    def on_file_drop(self, event):
        """
            Handles file drop events in the GUI. Copies dropped files into the base directory.

            Args:
                event: The file drop event containing the file paths.
        """
        # Extract the list of dropped files
        dropped_files = self.tk.splitlist(event.data)
        for file_path in dropped_files:
            # Ensure the dropped item is a file
            if os.path.isfile(file_path):
                # Define the target path
                target_path = os.path.join(self.base_path, os.path.basename(file_path))
                try:
                    # Copy the file to the base path
                    shutil.copy(file_path, target_path)
                    # Add the new file to the file tree
                    self.add_file_to_tree(target_path)
                    messagebox.showinfo("Success", f"{os.path.basename(file_path)} has been added.")
                except Exception as error_name:
                    # Handle copy errors
                    messagebox.showerror("Error", f"Failed to add file: {str(error_name)}")
            else:
                # Handle invalid items
                messagebox.showerror("Error", "Only files can be added.")

    def start_watching(self, path):
        """
            Initializes and starts the file system watcher to monitor changes in the specified directory.

            Args:
                path (str): The directory path to watch.
        """
        # Assign the event handler
        self.event_handler = FileEventHandler(self.file_tree)
        # Initialize the file system observer
        self.watcher = Observer()
        # Set up recursive watching
        self.watcher.schedule(self.event_handler, path, recursive=True)
        # Start the observer
        self.watcher.start()
        # Bind the window close event to `on_close`
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    @staticmethod
    def remove_readonly(path):
        """
            Removes the read-only attribute from a file or directory.

            Args:
                path (str): The directory path to modify.
        """
        # Traverse the directory structure
        for root, dirs, files in os.walk(path):
            for name in files:
                filepath = os.path.join(root, name)
                # Remove read-only flag from files
                os.chmod(filepath, stat.S_IWRITE)

            # Process directories
            for name in dirs:
                dir_path = os.path.join(root, name)
                # Remove read-only flag from directories
                os.chmod(dir_path, stat.S_IWRITE)

    def on_close(self):
        """
            Handles the application close event. Stops the file watcher and deletes the local folder.
        """

        # Stop the file system watcher if it exists
        if self.watcher:
            self.watcher.stop()
            self.watcher.join()
            self.watcher = None  # Clear the reference to the observer

        # Attempt to delete the user's local folder
        if os.path.exists(self.base_path):
            try:
                print(f"[DEBUG] Deleting user folder content: {self.base_path}")
                # Remove the folder and its contents
                shutil.rmtree(self.base_path)
                print(f"[INFO] User folder content in {self.base_path} deleted successfully.")
            except Exception as error_name:
                print(error_name)
                pass

        # Close the GUI window
        self.destroy()


if __name__ == "__main__":
    """
        Entry point for the application.
        Attempts to establish a connection with the server and initializes the login screen.
        If the server is unavailable, prompts the user to continue in offline mode.
    """
    try:
        # Discover the server's IP address dynamically
        print("Discovering server IP address...")
        discovered_host = discover_server_ip()
        print(f"Discovered server IP: {discovered_host}")

        # Create a client instance and attempt to connect to the server
        client = Client()
        client.connect()

        # Initialize the login/signup screen with the connected client
        login_screen = LoginSignupScreen(client)
        login_screen.mainloop()  # Start the Tkinter main event loop

    except Exception as error_name:
        # Handle any exceptions that occur during the connection attempt
        print(f"[WARNING] Unable to connect to server: {error_name}")

        # Prompt the user to continue in offline mode
        response = messagebox.askyesno(
            "Server Unavailable",
            "Cannot connect to the server. Would you like to continue in offline mode?"
        )

        if response:
            # If the user chooses to continue offline, initialize an offline client
            offline_client = OfflineClient()

            # Start the login/signup screen with the offline client
            login_screen = LoginSignupScreen(offline_client)
            login_screen.mainloop()  # Start the Tkinter main event loop
        else:
            # If the user chooses not to continue, log the closure and exit the application
            print("[INFO] Application closed by the user due to server unavailability.")
