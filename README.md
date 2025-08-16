# Python Honeypot

This repository contains a simple honeypot written in Python.  A honeypot is a decoy system designed to attract and detect attackers.  It works much like a pot of honey attracting flies: attackers interact with the honeypot instead of your real services, and the honeypot logs their behaviour【896866203660465†L20-L28】.  A basic honeypot consists of three parts—listeners, logging and service emulation【896866203660465†L95-L100】—and this project implements those using only the Python standard library.

## Features

* **Multi‑port listening** – listens on ports 21, 22, 80 and 443 by default.  Override the ports via the `HONEYPOT_PORTS` environment variable.
* **Service emulation** – sends realistic banners for FTP, SSH and HTTP/HTTPS.  All commands receive a generic response.
* **Threaded** – handles each connection in its own thread to support multiple concurrent interactions.
* **Logging** – writes each interaction (timestamp, source IP, port and data) to a JSON file in the `honeypot_logs` directory.

## Running the honeypot

> ⚠️ **Security caution:** This honeypot binds to privileged ports (<1024).  Running it on a production host or exposing it to the internet may have security implications.  Use at your own risk and consider running on high‑numbered ports when testing locally.

### Requirements

* Python 3.8 or later
* Root or administrator privileges if listening on ports below 1024

### Steps

1. Clone or download this repository.
2. Install Python 3 if not already installed.
3. (Optional) Specify alternative listening ports by exporting `HONEYPOT_PORTS`.  Use a comma‑separated list, for example:
   ```sh
   export HONEYPOT_PORTS="8000,2222,8080"
   ```
4. Run the honeypot:
   ```sh
   sudo python3 honeypot.py
   ```
   The script will start listeners on the specified ports.  When a connection arrives, it will print a message on the console and append a log entry to the JSON file in `honeypot_logs/`.

## Log files

Log files are stored in the `honeypot_logs` directory.  Each file is named `honeypot_YYYYMMDD.json` and contains one JSON object per line.  Each object has the following fields:

| Field      | Description                                   |
|-----------|-----------------------------------------------|
| `timestamp` | ISO 8601 timestamp when the data was received |
| `remote_ip` | IP address of the connecting client            |
| `port`      | Port on which the connection was received      |
| `data`      | Raw string data sent by the client             |

You can process these logs with your preferred tools or forward them to a SIEM for further analysis.

## License

This project is provided for educational purposes.  It is licensed under the MIT License.  See [LICENSE](LICENSE) for details.