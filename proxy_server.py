"""
proxy_server.py

A simple HTTPS proxy server that uses DNS over HTTPS (DoH) to resolve domain names.
"""

import socket
import threading

from doh_resolver import DoHResolver


class ProxyServer:
    """
    A simple proxy server that handles HTTPS connections using DoH for DNS resolution.
    """

    def __init__(self, host="127.0.0.1", port=4500):
        """
        Initializes the proxy server.

        Args:
            host (str): Host IP address to bind the server.
            port (int): Port to listen for incoming connections.
        """
        self.host = host
        self.port = port
        self.resolver = DoHResolver(
            doh_url="https://cloudflare-dns.com/dns-query?dns=",
            offline_dns={
                "twitter.com": "104.244.42.1",
                "cloudflare-dns.com": "203.32.120.226",
            },
            allow_insecure=True,
        )
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))

    def run(self):
        """
        Starts the proxy server and listens for incoming client connections.
        """
        self.server_socket.listen(100)
        print(f"[Proxy Server] Running on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"[Connection] Accepted from {addr}")
            threading.Thread(
                target=self.handle_client, args=(client_socket,), daemon=True
            ).start()

    def handle_client(self, client_socket):
        """
        Handles an individual client connection.

        Args:
            client_socket (socket.socket): The client's socket object.
        """
        try:
            request = client_socket.recv(4096)
            if b"CONNECT" in request:
                target, port = self.extract_target_port(request)
                ip = self.resolver.resolve(target)
                if not ip:
                    print(f"[DNS Failure] Could not resolve {target}")
                    client_socket.close()
                    return

                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((ip, port))
                client_socket.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

                self.forward(client_socket, server_socket)
            else:
                client_socket.close()
        except Exception as e:
            print(f"[Error] Client handling error: {e}")
            client_socket.close()

    def extract_target_port(self, request):
        """
        Extracts the target host and port from the HTTP CONNECT request.

        Args:
            request (bytes): The raw request data from the client.

        Returns:
            tuple[str, int]: The target host and port.
        """
        line = request.decode(errors="ignore").split("\n")[0]
        target = line.split()[1]
        if ":" in target:
            host, port = target.split(":")
        else:
            host, port = target, 443
        return host, int(port)

    def forward(self, client, server):
        """
        Forwards data between client and server sockets.

        Args:
            client (socket.socket): The client's socket.
            server (socket.socket): The server's socket.
        """
        threading.Thread(target=self._pipe, args=(client, server), daemon=True).start()
        threading.Thread(target=self._pipe, args=(server, client), daemon=True).start()

    def _pipe(self, src, dst):
        """
        Transfers data from one socket to another.

        Args:
            src (socket.socket): Source socket.
            dst (socket.socket): Destination socket.
        """
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except (ConnectionError, OSError):
            # Connection closed or interrupted
            pass
        finally:
            src.close()
            dst.close()
