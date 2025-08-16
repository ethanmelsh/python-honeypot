#!/usr/bin/env python3

"""
Simple multi‐service honeypot
=============================

This honeypot is a low–interaction trap that listens on multiple
commonly scanned ports and logs every connection attempt. It mimics
basic banners for FTP, SSH and HTTP services but does not provide
real functionality. Each incoming connection is handled in its own
thread; the server records the source IP address, port and data
received into a JSON log file.

The design is based on guidance from a freeCodeCamp article on
building a honeypot with Python, which notes that honeypots act as
decoy systems designed to attract and detect attackers, much like a
pot of honey attracts flies【896866203660465†L20-L28】.  The
article describes three core components of a basic honeypot: a
network listener, a logging system, and a service emulation layer
【896866203660465†L95-L100】.  This script implements these
components using only the Python standard library.

Usage:
    python3 honeypot.py

By default the honeypot listens on ports 21, 22, 80 and 443 on all
interfaces.  If you wish to change the listening ports, set the
``HONEYPOT_PORTS`` environment variable to a comma separated list of
ports before running the script.

Warning:
    Do not run this script on a production host without understanding
    the implications.  It binds to privileged ports (<1024) and
    requires root privileges.  Consider changing the ports to higher
    numbers when testing locally.
"""

import os
import socket
import threading
import datetime
import json
import time
import sys
from pathlib import Path


class Honeypot:
    """A simple multi‑port honeypot.

    The honeypot listens on a list of TCP ports and accepts
    connections.  For each connection it sends a fake banner,
    captures any data sent by the client and logs the interaction
    (timestamp, remote IP, port and data).  It responds with a
    generic message to discourage further commands.
    """

    DEFAULT_PORTS = [21, 22, 80, 443]

    def __init__(self, bind_ip: str = "0.0.0.0", ports=None, log_dir: str = "honeypot_logs"):
        self.bind_ip = bind_ip
        # Determine ports to listen on; environment variable overrides defaults
        if ports is None:
            env_ports = os.getenv("HONEYPOT_PORTS")
            if env_ports:
                try:
                    ports = [int(p) for p in env_ports.split(',') if p.strip()]
                except ValueError:
                    print(f"Invalid HONEYPOT_PORTS value: {env_ports}")
                    ports = self.DEFAULT_PORTS
            else:
                ports = self.DEFAULT_PORTS
        self.ports = ports
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        # Create a daily log file
        timestamp = datetime.datetime.now().strftime('%Y%m%d')
        self.log_file = self.log_dir / f"honeypot_{timestamp}.json"

    def log_activity(self, port: int, remote_ip: str, data: bytes) -> None:
        """Write activity to the JSON log file."""
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "port": port,
            "data": data.decode('utf-8', errors='ignore')
        }
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                json.dump(entry, f)
                f.write('\n')
        except Exception as e:
            # Print errors but do not crash
            print(f"[!] Failed to write log entry: {e}")

    def handle_connection(self, client_socket: socket.socket, remote_ip: str, port: int) -> None:
        """Handle an individual connection.

        Sends a banner appropriate to the port, receives data in a loop,
        logs it and replies with a generic response.
        """
        # Basic banners for common services
        service_banners = {
            21: "220 FTP server ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"
        }
        try:
            # Send service banner if defined
            banner = service_banners.get(port)
            if banner:
                client_socket.sendall(banner.encode())
            # Receive data until client closes the connection
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                self.log_activity(port, remote_ip, data)
                # Respond with a dummy message
                client_socket.sendall(b"Command not recognized.\r\n")
        except Exception as e:
            print(f"[!] Error handling connection on port {port}: {e}")
        finally:
            client_socket.close()

    def start_listener(self, port: int) -> None:
        """Start a TCP listener on the specified port."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow reuse of the address in TIME_WAIT state
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_ip, port))
            server.listen(5)
            print(f"[*] Listening on {self.bind_ip}:{port}")
            while True:
                client, addr = server.accept()
                remote_ip, _remote_port = addr
                print(f"[*] Accepted connection from {remote_ip}:{_remote_port} on port {port}")
                # Handle connection in separate thread
                handler = threading.Thread(target=self.handle_connection, args=(client, remote_ip, port))
                handler.daemon = True
                handler.start()
        except Exception as e:
            print(f"[!] Error starting listener on port {port}: {e}")

    def run(self) -> None:
        """Run the honeypot by starting listeners on all configured ports."""
        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.start_listener, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)
        try:
            # Keep the main thread alive while listeners run in the background
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt received. Shutting down honeypot...")
            for t in threads:
                # There is no clean shutdown for threads using sockets. We rely on process exit.
                pass
            sys.exit(0)


def main():
    honeypot = Honeypot()
    honeypot.run()


if __name__ == '__main__':
    main()