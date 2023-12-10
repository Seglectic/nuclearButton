# ╭────────────────────────────────────────────────────────────────────────────────────────────╮
# │                                        nuclearButton.py                                    │
# │  Runs a simple HTTP server that listens for requests to shut down the computer.            │
# │  Request must include a password parameter that matches the encrypted file on the server.  │
# │  Example request: http://localhost:8080/shutdown?password=12345678                         │
# │  Use -h to see the available options.                                                      │
# ╰────────────────────────────────────────────────────────────────────────────────────────────╯
import os
import sys
import http.server
import socketserver
import argparse
from urllib.parse import urlparse, parse_qs
from cryptography.fernet import Fernet

# ╭────────────────────────╮
# │  Save / Load Key file  │
# ╰────────────────────────╯
# File to store the encrypted launch code
KEY_FILE = "launchCode.key"
KEY_FILE_CIPHER = "launch.key"

def generate_or_open_key():                            # Check if the key file exists else generate a new key
    if os.path.exists(KEY_FILE_CIPHER):                # Load the key from the file
        with open(KEY_FILE_CIPHER, "rb") as key_file:
            return key_file.read()
    else:                                              # Generate a new key and save it to the file
        key = Fernet.generate_key()
        with open(KEY_FILE_CIPHER, "wb") as key_file:
            key_file.write(key)
        return key

# Load the key and create the cipher suite for encryption / decryption
SECRET_KEY = generate_or_open_key()
cipher_suite = Fernet(SECRET_KEY)

# ╭──────────────────────╮
# │  Command Parameters  │
# ╰──────────────────────╯
def set_launch_code(): 
    launch_code = input("Enter the launch code: ")
    encrypted_code = cipher_suite.encrypt(launch_code.encode())
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(encrypted_code)
    print("Launch code set successfully.")
    sys.exit(0)

def clear_launch_code():
    if os.path.exists(KEY_FILE):
        os.remove(KEY_FILE)
        print("Launch code cleared successfully.")
    else:
        print("No launch code to clear.")

def print_launch_code():
    try:
        with open(KEY_FILE, "rb") as key_file:
            encrypted_code = key_file.read()
            launch_code = cipher_suite.decrypt(encrypted_code).decode()
        print(f"Launch code: {launch_code}")
    except FileNotFoundError:
        print("Launch code not set. Use --set-launch-code to set it.")

def load_launch_code():
    try:
        with open(KEY_FILE, "rb") as key_file:
            encrypted_code = key_file.read()
            launch_code = cipher_suite.decrypt(encrypted_code).decode()
        return launch_code
    except FileNotFoundError:
        print("Launch code not set. Use --set-launch-code to set it.")
        sys.exit(1)

# ╭────────────────────────────╮
# │  Process the http request  │
# ╰────────────────────────────╯
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        
        # Get the path without leading or trailing slashes
        path = parsed_url.path.strip('/')

        if path == "shutdown":
            query_params = parse_qs(parsed_url.query)
            
            # Get the password from the request
            password = query_params.get("password", [""])[0]

            # Check if the password matches the launch code
            if password == launch_code:
                print("Received valid shutdown request. Shutting down...")
                # Add platform-specific shutdown commands here
                if sys.platform.startswith('win'):
                    os.system("shutdown /s /t 1")  # Windows
                elif sys.platform.startswith('linux'):
                    os.system("shutdown now")  # Linux
                elif sys.platform.startswith('darwin'):
                    os.system("shutdown -h now") # Mac
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Shutting down...")
            else:
                print("Invalid password. Ignoring shutdown request.")
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")
        else:
            # If the request is for any other path, return a 404 response
            self.send_response(404)
            self.end_headers()
            
# ╭─────────────────────────────────────╮
# │  Parse the args and run the server  │
# ╰─────────────────────────────────────╯
def parse_arguments():
    parser = argparse.ArgumentParser(description="Simple HTTP server for remote shutdown with a launch code.")
    parser.add_argument("--set-launch-code", action="store_true", help="Set the launch code.")
    parser.add_argument("--clear-launch-code", action="store_true", help="Clear the launch code.")
    parser.add_argument("--print-launch-code", action="store_true", help="Print the launch code.")
    parser.add_argument("--port", type=int, default=8080, help="Set the port to run on.")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    if args.set_launch_code:
        set_launch_code()

    if args.clear_launch_code:
        clear_launch_code()

    if args.print_launch_code:
        print_launch_code()
        sys.exit(0)

    launch_code = load_launch_code()

    with socketserver.TCPServer(("", args.port), RequestHandler) as httpd:
        print(f"Serving on port {args.port}")
        httpd.serve_forever()