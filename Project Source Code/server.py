import socket
import platform
import shutil
import ssl
import sys
from ssl import SSLSocket
import subprocess
import threading
import os
import json
import bcrypt
import logging
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configuring logging to display DEBUG level messages
logging.basicConfig(level=logging.DEBUG)  # DEBUG

# Generate a 256-bit random encryption key for secure data handling
encryption_key = os.urandom(32)

# Server Configuration
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 465
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
CA_FILE = "ca.pem"  # The Certificate Authority's certificate

# Determine the current directory dynamically
if getattr(sys, 'frozen', False):  # Check if running as a frozen .exe
    current_directory = os.path.dirname(sys.executable)  # Path to the .exe directory
else:
    # Get the current directory where server.py is located
    current_directory = os.path.dirname(os.path.abspath(__file__))

# Set the server folder path dynamically
SERVER_FOLDER_PATH = os.path.join(current_directory, "client_folder")

# File to store user credentials in JSON format
CREDENTIALS_FILE = 'credentials.json'

# Variables to track the current logged-in user
current_username = ""
current_hashed_password = b""

# List to manage connected client connections
clients = []


def send_server_ip(server_ip, broadcast_port=12345, interval=5):
    """
    Sends a periodic broadcast with the server's IP address.
    Args:
        server_ip (str): The IP address to broadcast.
        broadcast_port (int): The port to use for broadcasting.
        interval (int): The interval (in seconds) between broadcasts.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        message = server_ip
        print(f"Broadcasting server IP: {message} on port {broadcast_port}")
        while True:
            sock.sendto(message.encode(), ('<broadcast>', broadcast_port))
            time.sleep(interval)


def hide_folder(folder_path):
    """
       Hide a folder on the system based on the operating system.

       Args:
           folder_path (str): The path of the folder to hide.

       Returns:
           str: The modified folder path if applicable, otherwise the original path.
    """
    # Hide the folder on Windows
    if platform.system() == "Windows":
        # Use the Windows 'attrib' command to set the hidden attribute on the folder
        subprocess.call(["attrib", "+h", folder_path])

    # Hide the folder on UNIX-based systems (macOS/Linux) by prefixing with a dot
    elif platform.system() in ["Linux", "Darwin"]:
        # Create a new hidden folder path by adding a dot prefix to the folder name
        hidden_path = os.path.join(os.path.dirname(folder_path), f".{os.path.basename(folder_path)}")

        # Check if a folder with the new name doesn't already exist
        if not os.path.exists(hidden_path):
            # Rename the folder to the hidden path
            os.rename(folder_path, hidden_path)
            print(f"[DEBUG] Folder renamed to {hidden_path} for hidden status.")
        return hidden_path
    return folder_path


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
            for dir in dirs:
                dir_path = os.path.join(root, dir)
                os.chmod(dir_path, stat.S_IWRITE)
                os.system(f'attrib -h "{dir_path}"')


def encrypt_data(data, internal_key):
    """
        Encrypts the given data using AES encryption in CBC mode with PKCS7 padding.

        Args:
            data (bytes): The plaintext data to encrypt.
            internal_key (bytes): A 32-byte encryption key.

        Returns:
            bytes: The initialization vector (IV) concatenated with the encrypted data.
    """
    # Generate a random 16-byte initialization vector (IV) for encryption
    iv = os.urandom(16)

    # Create an AES cipher object in CBC mode using the provided internal key and IV
    cipher = Cipher(algorithms.AES(internal_key), modes.CBC(iv), backend=default_backend())

    # Initialize the encryptor for performing encryption
    encryptor = cipher.encryptor()

    # Create a PKCS7 padder to ensure data is a multiple of the block size (128 bits)
    padder = padding.PKCS7(128).padder()

    # Apply padding to the input data to make it suitable for encryption
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data and concatenate it with the IV
    return iv + encryptor.update(padded_data) + encryptor.finalize()


def decrypt_data(encrypted_data, internal_key):
    """
        Decrypts the given encrypted data using AES in CBC mode with PKCS7 padding.

        Args:
            encrypted_data (bytes): The encrypted data to decrypt, including the IV.
            internal_key (bytes): A 32-byte decryption key.

        Returns:
            bytes: The decrypted plaintext data.
    """
    # Extract the first 16 bytes as the initialization vector (IV)
    iv = encrypted_data[:16]

    # Create an AES cipher object in CBC mode using the provided internal key and IV
    cipher = Cipher(algorithms.AES(internal_key), modes.CBC(iv), backend=default_backend())

    # Initialize the decryptor for performing decryption
    decryptor = cipher.decryptor()

    # Create a PKCS7 unpadder to remove padding after decryption
    unpadder = padding.PKCS7(128).unpadder()

    # Decrypt the encrypted data (excluding the IV) and remove padding
    decrypted_data = unpadder.update(decryptor.update(encrypted_data[16:]) + decryptor.finalize()) + unpadder.finalize()

    # Return the decrypted plaintext data
    return decrypted_data


def load_credentials():
    """
        Loads user credentials from a JSON file.

        Returns:
            dict: A dictionary containing the credentials if the file exists, otherwise an empty dictionary.
    """
    # Check if the credentials file exists
    if not os.path.exists(CREDENTIALS_FILE):
        # Return an empty dictionary if the file does not exist
        return {}

    # Open the credentials file in read mode
    with open(CREDENTIALS_FILE, 'r') as file:
        # Load and return the credentials from the JSON file
        return json.load(file)


def save_credentials(credentials):
    """
      Saves user credentials to a JSON file.

      Args:
          credentials (dict): A dictionary containing the user credentials to save.
    """
    # Open the credentials file in write mode
    with open(CREDENTIALS_FILE, 'w') as file:
        # Save the credentials dictionary to the file in JSON format
        json.dump(credentials, file)


def register_user(username, password):
    """
        Registers a new user by saving their username and hashed password.

        Args:
            username (str): The username of the user to register.
            password (str): The plaintext password of the user.

        Returns:
            tuple: A tuple containing a boolean and a message.
                   - True and a success message if registration is successful.
                   - False and an error message if the username already exists.
    """
    # Load existing credentials from the JSON file
    credentials = load_credentials()

    # Check if the username is already registered
    if username in credentials:
        return False, "Username already exists"

    # Hash the plaintext password using bcrypt with a generated salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Save the username and hashed password to the credentials dictionary
    credentials[username] = hashed_password.decode('utf-8')

    # Save the updated credentials back to the JSON file
    save_credentials(credentials)

    # Return success message upon successful registration
    return True, "Registration successful"


def authenticate_user(username, password):
    """
        Authenticates a user by checking the entered password against the stored hashed password.

        Args:
            username (str): The username of the user attempting to log in.
            password (str): The plaintext password provided by the user.

        Returns:
            tuple: A tuple containing a boolean and a message.
                   - True and a success message if authentication is successful.
                   - False and an error message if authentication fails.
    """
    # Track the current logged-in user's credentials globally
    global current_username, current_hashed_password

    # Load existing credentials from the JSON file
    credentials = load_credentials()  # Load credentials from file

    # Check if the username exists in the loaded credentials
    if username in credentials:
        # Retrieve the stored hashed password for the username
        hashed_password = credentials[username].encode('utf-8')

        # Verify the entered password against the stored hash using bcrypt
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            # Update global variables with the current user's information
            current_username = username
            current_hashed_password = hashed_password

            # Log a success message and return authentication success
            print(f"User {username} authenticated successfully.")
            return True, "Login successful"
        else:
            # Log a message indicating password mismatch
            print(f"Password mismatch for user {username}.")
    else:
        # Log a message indicating that the username was not found
        print(f"Username {username} not found.")

    # Return authentication failure with an error message
    return False, "Invalid username or password"


def delete_user(username, connection: SSLSocket):
    """
       Deletes a user by removing their credentials and associated folder from the server.

       Args:
           username (str): The username of the user to be deleted.
           connection (socket): The active socket connection to communicate with the client.

       Returns:
           tuple: A tuple containing a boolean and a message.
                  - True and a success message if deletion is successful.
                  - False and an error message if the user does not exist.
    """
    # Load stored credentials from the JSON file
    credentials = load_credentials()  # Load stored credentials from file

    # Debug: Print the username being deleted
    print(f"Attempting to delete user: {username}")

    # Check if the username exists in the credentials
    if username in credentials:
        # Remove the user from the credentials dictionary
        del credentials[username]
        # Save the updated credentials back to the JSON file
        save_credentials(credentials)

        # Construct the path to the user's folder on the server
        client_folder_name = f"client_folder_{username}"
        server_user_folder_path = os.path.join(SERVER_FOLDER_PATH, client_folder_name)

        # Check if the user's folder exists on the server
        if os.path.exists(server_user_folder_path):
            # Delete the user's folder and its contents
            shutil.rmtree(server_user_folder_path)
            # Debug: Confirm successful deletion of the folder
            print(f"Server folder '{server_user_folder_path}' deleted successfully.")

        # Notify the client of successful removal
        connection.send(b"Remove successful")
        # Return success status and message
        return True, "User deleted successfully"
    else:
        # Debug: Inform that the username was not found
        print("Username not found in credentials.")
        # Notify the client of the failure
        connection.send(b"Wrong password or user not found")
        # Return failure status and message
        return False, "User not found"


def derive_encryption_key(username, hashed_password):
    """
      Derives a 256-bit encryption key using PBKDF2 with SHA-256.

      Args:
          username (str): The username of the user, used as part of the key derivation.
          hashed_password (bytes): The hashed password of the user.

      Returns:
          bytes: A 32-byte derived encryption key.
    """

    # Predefined salt for the key derivation function (unique to the application)
    salt = b'PancakesAreAwsome'

    # Convert the username to bytes format for use in the key derivation process
    username_bytes = username.encode('utf-8')  # Convert username to bytes

    # Initialize the PBKDF2 key derivation function with the specified parameters
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # Derive the encryption key by combining the username bytes and the hashed password
    derived_key = kdf.derive(username_bytes + hashed_password)

    # Return the derived encryption key
    return derived_key


def send_folder_over_socket(connection: SSLSocket, folder_path):
    """
        Sends the contents of a folder over a socket connection, decrypting files before transfer.

        Args:
            connection (socket): The active socket connection to communicate with the client.
            folder_path (str): The path of the folder to send.
    """

    if not current_hashed_password:
        raise ValueError("current_hashed_password is not initialized. Authentication is required.")

    # Derive an encryption key for file decryption based on the current user
    local_encryption_key = derive_encryption_key(current_username, current_hashed_password)

    # Walk through the directory tree, including all subdirectories and files
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            # Get the full path to the file
            file_path = os.path.join(root, file)

            # Calculate the relative path for file identification during transfer
            relative_path = os.path.relpath(file_path, folder_path)

            # Get the size of the file
            file_size = os.path.getsize(file_path)

            # Send metadata (file name and size) to the client
            connection.send(f"FILE {relative_path},{file_size}".encode())
            print(f"Yuval FILE {relative_path},{file_size}".encode())
            # Wait for the client to respond with "READY" to proceed
            response = connection.recv(1024).decode().strip()
            if response == "READY":
                # Open the file in binary read mode
                with open(file_path, 'rb') as f:
                    # Read the encrypted data from the file
                    encrypted_data = f.read()
                    # Decrypt the data using the derived encryption key
                    decrypted_data = decrypt_data(encrypted_data, local_encryption_key)

                    # Log decrypted data size to verify
                    print(f"[DEBUG] Decrypted data size for {relative_path}: {len(decrypted_data)} bytes")

                    # Check if decryption was successful
                    if not decrypted_data:
                        print(f"[ERROR] Decryption failed for {relative_path}")
                        # Skip the file if decryption fails
                        continue

                    # Send the decrypted data to the client
                    connection.sendall(decrypted_data)

                # Send EOF marker to indicate the end of the file
                connection.send(b"EOF")

                # Wait for the client's acknowledgment of EOF
                connection.recv(1024)

                # Introduce a small delay to prevent data overload on the client side
                time.sleep(0.1)

    # Signal that the folder transfer is complete
    connection.send(b"DONE")
    # Wait for the client's final acknowledgment
    connection.recv(1024)


def handle_client(connection: SSLSocket, address):
    try:
        authenticated = False
        username = None

        while not authenticated:
            connection.send("Do you want to register, login, or exit? (register/login/exit): ".encode())
            action = connection.recv(1024).decode().strip().lower()

            if action == 'exit':
                # Handle client disconnection
                print(f"[EXIT] {address} disconnected.")
                connection.close()
                # Exit the function as the client chose to leave
                return

            if action == 'login':
                # Expect the client to send both username and password together
                credentials = connection.recv(1024).decode().strip()

                try:
                    # Split the credentials received as "username,password"
                    username, password = credentials.split(",")
                except ValueError:
                    connection.send("Invalid credentials format.".encode())
                    continue

                # Authenticate the user using the credentials
                success, message = authenticate_user(username, password)

                # Send back success or failure message to the client
                connection.send(message.encode())

                # If authentication was successful, mark the user as authenticated
                if success:
                    print(f"[LOGIN SUCCESS] {username} logged in successfully.")

                    authenticated = True  # Set authenticated to True to break out of the login loop
                    break  # Exit the login attempt loop
                else:
                    print(f"[LOGIN FAILURE] Failed login attempt from {address}.")
                    # Clear any residual data from the connection buffer
                    connection.recv(1024)  # Flush buffer to avoid stale data

            elif action == 'register':
                # Expect the client to send both username and password together
                credentials = connection.recv(1024).decode().strip()

                try:
                    # Split the credentials received as "username,password"
                    username, password = credentials.split(",")
                except ValueError:
                    connection.send("Invalid credentials format.".encode())
                    continue

                # Register the new user
                success, message = register_user(username, password)
                connection.send(message.encode())  # Send success or failure message

                if success:
                    print(f"[REGISTRATION SUCCESS] {username} registered successfully.")
                    authenticated = True  # Automatically log in after successful registration

                    # Create the user's folder on the server
                    client_folder_name = f"client_folder_{username}"
                    server_user_folder_path = os.path.join(SERVER_FOLDER_PATH, client_folder_name)
                    if not os.path.exists(server_user_folder_path):
                        os.makedirs(server_user_folder_path)
                        print(f"[FOLDER CREATED] Folder '{server_user_folder_path}' created for {username}.")
                else:
                    print(f"[REGISTRATION FAILURE] Failed registration attempt from {address}.")

        # Once authenticated, sync the user's folder if it exists
        client_folder_name = f"client_folder_{username}"
        server_user_folder_path = os.path.join(SERVER_FOLDER_PATH, client_folder_name)

        if  not  os.path.exists(server_user_folder_path):
            # Create the user's folder if it doesn't exist
            print(f"[NO FOLDER] No folder exists for {username}, creating one.")
            os.makedirs(server_user_folder_path)

        print(f"[NEW CONNECTION] {address} authenticated as {username}.")
        clients.append(connection)

        while True:
            # Receive data from the client (file operations, sync requests, etc.)
            data = connection.recv(1024)
            if not data:
                # Exit the loop if no data is received
                break

            data_decoded = data.decode().strip()

            if "SEND_FILE" in data_decoded:
                # Handle a file upload request from the client
                file_info = data_decoded.split(",")
                if len(file_info) == 3:
                    filename, file_size = file_info[1].strip(), int(file_info[2].strip())
                    print(f"[FILE SEND REQUEST] File: {filename}, Size: {file_size} bytes")
                    receive_file_from_client(connection, server_user_folder_path, filename)
                    hide_folder(server_user_folder_path)
                else:
                    print("[INVALID FILE INFO] Incorrect file information format.")
                continue  # Skip further command handling for this iteration

            elif data_decoded.startswith("DELETE_FILE"):
                # Handle a request to delete a specific file
                try:
                    _, filename = data_decoded.split(",", 1)
                    filename = filename.strip()
                    print(f"[DEBUG] Parsed filename for DELETE_FILE: '{filename}'")
                    file_path = os.path.join(server_user_folder_path, filename)

                    if os.path.exists(file_path):
                        os.remove(file_path)
                        print(f"[INFO] Deleted '{filename}' on server.")
                        connection.send(b"ACK")
                    else:
                        print(f"[WARNING] File '{filename}' not found.")
                        connection.send(b"FILE_NOT_FOUND")
                except ValueError:
                    print("[ERROR] DELETE_FILE command format is incorrect.")
                    connection.send(b"ERROR")
                continue

            elif data_decoded.startswith("CREATE") or data_decoded.startswith("MODIFY"):
                # Handle file creation or modification events
                try:
                    command, filename = data_decoded.split(" ", 1)
                    print(f"[FILE EVENT] {command} event for {filename} from {username}")
                    receive_file_from_client(connection, server_user_folder_path, filename.strip())
                except ValueError:
                    print("[ERROR] CREATE/MODIFY command format is incorrect.")
                    connection.send(b"ERROR")
                continue

            elif data_decoded == "GET_USER_FOLDER":
                # Handle a folder sync request from the client
                print(f"[SYNC REQUEST] Sync requested by {username}")
                send_folder_over_socket(connection, server_user_folder_path)
                continue

            elif data_decoded == "LIST_FILES":
                # List files in the user's folder
                files = os.listdir(server_user_folder_path)
                file_list = ",".join(files)
                connection.send(file_list.encode())
                continue

            elif data_decoded == "LOGOUT":
                # Handle logout requests
                print(f"[LOGOUT] {username} logged out.")
                connection.send(b"Logout successful")
                break

            elif data_decoded == "Delete_user":
                # Handle user deletion requests
                # Acknowledge delete request
                connection.send(b"Delete_user_ack")
                credentials = connection.recv(1024).decode().strip().split(',')
                if len(credentials) == 2:
                    username, password = credentials
                    success, message = authenticate_user(username, password)
                    if success:
                        success, message = delete_user(username, connection)
                        connection.send(
                            b"Remove successful" if success else b"Error removing client folder from server")
                    else:
                        connection.send(b"Wrong password (server)")
                else:
                    connection.send(b"Wrong password")

            elif data_decoded == "DELETE_ALL":
                # Deletes all files and subfolders in the user's server folder.
                try:
                    # Ensure folder and contents are writable and visible
                    make_writable_and_visible(server_user_folder_path)

                    # Walk through the folder and delete all files and subfolders
                    for root, dirs, files in os.walk(server_user_folder_path):
                        for file in files:
                            os.remove(os.path.join(root, file))
                        for dir in dirs:
                            shutil.rmtree(os.path.join(root, dir))

                    connection.send(b"ACK")
                    print(f"[INFO] All files and folders deleted in '{server_user_folder_path}'.")
                except Exception as e:
                    print(f"[ERROR] Failed to delete all files: {e}")
                    connection.send(b"ERROR")

            else:
                # Handle unknown commands
                print(f"[UNKNOWN COMMAND] {data_decoded}")

    except Exception as e:
        # Log any exceptions that occur
        print(f"[ERROR] Exception occurred while handling {address}: {e}")
    finally:
        # Cleanup resources on disconnection
        if connection in clients:
            clients.remove(connection)
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            print(f"[ERROR] Could not shut down connection cleanly: {e}")
        connection.close()
        print(f"[DISCONNECTED] {address} disconnected.")


def receive_file_from_client(connection: SSLSocket, folder_path, filename):
    """
    Receives a file from the client, encrypts it, and stores it on the server.

    Args:
        connection (socket): The socket connection to communicate with the client.
        folder_path (str): The path of the folder where the file will be stored.
        filename (str): The name of the file being received from the client.
    """
    if not current_hashed_password:
        raise ValueError("current_hashed_password is not initialized. Authentication is required.")

    # Derive the encryption key based on the current user's credentials
    internal_key = derive_encryption_key(current_username, current_hashed_password)

    # Construct the full path where the file will be saved
    file_path = os.path.join(folder_path, filename)

    # Ensure the directory structure exists for the file path
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # Signal the client that the server is ready to receive the file
    connection.send(b"READY")
    print(f"[DEBUG] Server ready to receive file: {filename}")

    try:
        # Initialize a buffer to collect all incoming file data
        data = b""
        while True:
            # Receive a chunk of data from the client
            bytes_read = connection.recv(8192)

            # Check for the EOF (End of File) marker sent by the client
            if bytes_read == b"EOF":
                print(f"[DEBUG] EOF received for {filename}")
                break

            # Append the received data to the buffer
            data += bytes_read

        # Encrypt the collected file data before saving it to the server
        encrypted_data = encrypt_data(data, internal_key)

        # Write the encrypted data to the designated file path
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        # Notify the client that the file has been successfully received and processed
        connection.send(b"ACK")
        print(f"[DEBUG] ACK sent for {filename}")

    except Exception as e:
        # Log any errors that occur during the file reception process
        logging.error(f"[ERROR] Failed to receive file {filename}: {e}")
        # Notify the client that an error occurred
        connection.send(b"ERROR")


def start_server():
    """
     Starts the server, initializes SSL for secure communication, and listens for client connections.
     Each client connection is handled in a separate thread.
     """
    # Get the server's IP address
    server_ip = socket.gethostbyname(socket.gethostname())
    print(f"[SERVER IP] Server IP: {server_ip}")

    # Start broadcasting the server's IP in a separate thread
    threading.Thread(target=send_server_ip, args=(server_ip,), daemon=True).start()

    # Create an SSL context for secure communication using the TLS server protocol
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Load the server's SSL certificate and private key
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # Load the Certificate Authority (CA) certificate
    ssl_context.load_verify_locations(CA_FILE)

    # Enable multithreading for SSL connections to handle multiple clients concurrently
    ssl_context.enable_multithread = True

    # Create a TCP socket for the server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the server to the specified host and port
    server.bind((SERVER_HOST, SERVER_PORT))

    # Start listening for incoming connections, with a maximum backlog of 5
    server.listen(5)

    print(f"[LISTENING] Server is listening on {SERVER_HOST}:{SERVER_PORT}")

    # Ensure the server folder exists; create it if it does not
    if not os.path.exists(SERVER_FOLDER_PATH):
        os.makedirs(SERVER_FOLDER_PATH)
        print(f"[SERVER FOLDER CREATED] Server folder '{SERVER_FOLDER_PATH}' created.")

    # Attempt to hide the server folder based on the operating system
    hidden_folder_path = hide_folder(SERVER_FOLDER_PATH)
    print(f"[DEBUG] Server folder path set to '{hidden_folder_path}'")

    # Main loop to accept and handle client connections
    while True:
        # Accept a new client connection
        client_socket, client_address = server.accept()

        # Wrap the client socket with SSL for secure communication
        # secure_socket = ssl_context.wrap_socket(client_socket, server_side=True)
        secure_socket = ssl_context.wrap_socket(client_socket, server_side=True)

        # Create a new thread to handle the client connection
        thread = threading.Thread(target=handle_client, args=(secure_socket, client_address))

        # Start the thread to process the client connection
        thread.start()

        # Print the current number of active connections (subtracting the main thread)
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == "__main__":
    """
      The main entry point of the script. Executes the `start_server` function
      when the script is run directly.
    """

    # Start the server to begin listening for client connections
    start_server()
