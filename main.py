import os
import logging
import argparse
import hashlib
import socket
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from paramiko import RSAKey, SSHException, Transport, ServerInterface, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import subprocess

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler('server.log', 'a')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

# Constants
MAX_AUTH_ATTEMPTS = 3
BLOCK_TIME = timedelta(minutes=5)
auth_attempts = defaultdict(int)
first_auth_attempt = {}
blocked_ips = {}
auth_lock = threading.Lock()

def get_rsa_keys(script_dir, regenerate=False):
    public_key_path = os.path.join(script_dir, "id_rsa.pub")
    private_key_path = os.path.join(script_dir, "id_rsa")
    if regenerate or not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        with open(private_key_path, "wb") as priv_file:
            priv_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
        with open(public_key_path, "wb") as pub_file:
            pub_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
    private_key = RSAKey(filename=private_key_path)
    return private_key

class SSHServer(ServerInterface):
    def __init__(self, allowed_users, client_ip):
        self.allowed_users = allowed_users
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        with auth_lock:
            if self.client_ip in blocked_ips:
                block_time = blocked_ips[self.client_ip]
                if datetime.now() < block_time:
                    logger.warning(f"Blocked IP {self.client_ip} tried to authenticate")
                    return AUTH_FAILED
                else:
                    del blocked_ips[self.client_ip]
                    del auth_attempts[self.client_ip]
                    del first_auth_attempt[self.client_ip]

            auth_attempts[self.client_ip] += 1
            attempt_count = auth_attempts[self.client_ip]

            if self.client_ip not in first_auth_attempt:
                first_auth_attempt[self.client_ip] = datetime.now()

            if attempt_count > MAX_AUTH_ATTEMPTS:
                blocked_ips[self.client_ip] = datetime.now() + BLOCK_TIME
                logger.warning(f"Max auth attempts reached for {username} from IP {self.client_ip}, blocking IP for {BLOCK_TIME}")
                return AUTH_FAILED

            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if username in self.allowed_users and self.allowed_users[username] == hashed_password:
                logger.info(f"Successful login for {username} from IP {self.client_ip} with password: {password}")
                return AUTH_SUCCESSFUL
            else:
                logger.warning(f"Failed auth attempt {attempt_count} for {username} from IP {self.client_ip} with password: {password}")
                return AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
  
    def check_channel_shell_request(self, channel):
        return True
  
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_client(client, client_ip, server_key, allowed_users):
    transport = Transport(client)
    transport.add_server_key(server_key)
    server = SSHServer(allowed_users, client_ip)
    try:
        transport.start_server(server=server)
    except SSHException as e:
        logger.error(f"SSH negotiation failed: {e}")
        return

    chan = transport.accept()
    if chan is None:
        logger.error("Channel not established.")
        return

    try:
        chan.send("\r\nWelcome to the SSH server\r\n")
        chan.send("Type 'exit' or 'quit' to disconnect.\r\n")
        current_dir = os.path.expanduser("~")  # Start in the home directory

        while True:
            chan.send(f"{os.getlogin()}@{socket.gethostname()}:{current_dir}$ ")
            command = ''
            while True:
                char = chan.recv(1).decode('utf-8')
                if char in ('\r', '\n'):
                    break
                command += char
                chan.send(char)

            command = command.strip()
            if command.lower() in ('exit', 'quit'):
                chan.send("\r\n")
                break

            logger.info(f"Command executed from {client_ip}: {command}")

            if command:
                chan.send("\r\n")

            if command.startswith('cd '):
                _, _, path = command.partition(' ')
                try:
                    os.chdir(os.path.join(current_dir, path))
                    current_dir = os.getcwd()
                except Exception as e:
                    chan.send(f"No such directory: {path}\r\n")
            else:
                try:
                    process = subprocess.Popen(
                        command, shell=True, cwd=current_dir,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()

                    # Correctly handle and send command output
                    chan.send(stdout.decode('utf-8').replace('\n', '\r\n'))
                    if stderr:
                        chan.send(stderr.decode('utf-8').replace('\n', '\r\n'))
                except Exception as e:
                    chan.send(str(e) + "\r\n")
    finally:
        chan.close()

def start_server(host, port, server_key, allowed_users):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(100)
    logger.info(f'SSH server started on {host}:{port}')
    while True:
        client, addr = server_socket.accept()
        logger.info(f'Connection attempt from {addr[0]}:{addr[1]}')
        threading.Thread(target=handle_client, args=(client, addr[0], server_key, allowed_users)).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Custom SSH server implementation.')
    parser.add_argument('--host', default='0.0.0.0', help='Host address for the SSH server')
    parser.add_argument('--port', type=int, default=2222, help='Port number for the SSH server')
    args = parser.parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_key = get_rsa_keys(script_dir)
    allowed_users = {'admin': hashlib.sha256('secret'.encode()).hexdigest()}
    start_server(args.host, args.port, server_key, allowed_users)
