# SSH-Honeypot
SSH Honeypot using Python

## Features
- Logs authentication attempts with IP addresses and passwords.
- Blocks IP addresses after a specified number of failed attempts.
- Logs commands executed by authenticated users.
- Simulates a basic shell environment.

## Requirements
- Python 3.6+
- Paramiko
- Cryptography

## Installation
1. **Clone the repository:**
    ```bash
    git clone https://github.com/Tharbouch/ssh-honeypot.git
    cd ssh-honeypot
    ```

2. **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. **Run the honeypot:**
    ```bash
    python honeypot.py --host <host> --port <port>
    ```
    - `--host`: Host address for the SSH server (default: `0.0.0.0`).
    - `--port`: Port number for the SSH server (default: `2222`).

2. **Default credentials:**
    The script uses a default allowed user `admin` with password `secret`. Modify this in the script or extend the allowed users as needed.

## Logging
- Logs are stored in `server.log` with timestamps, IP addresses, usernames, passwords, and executed commands.

## RSA Keys
- The script generates RSA keys if they do not exist in the script directory. These keys are used to authenticate the server.

## Customization
- Customize the maximum number of authentication attempts and the block time by modifying the `MAX_AUTH_ATTEMPTS` and `BLOCK_TIME` constants in the script.

## Example
```bash
python honeypot.py --host 0.0.0.0 --port 2222
```
## Contributing
Feel free to fork this repository and contribute by submitting pull requests. Any enhancements and bug fixes are welcome.

License
This project is licensed under the MIT License - see the LICENSE file for details.
