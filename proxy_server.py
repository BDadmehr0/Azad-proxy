"""
Module implementing a simple multithreaded proxy server with DoH DNS resolution.
"""

import json
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from doh_resolver import DoHResolver

logger = logging.getLogger("ProxyServer")


class ProxyServer:
    """
    Proxy server that handles HTTP CONNECT requests and resolves domains via DoH.

    Attributes:
        host (str): Proxy host address.
        port (int): Proxy port.
        max_workers (int): Maximum concurrent worker threads.
        dns_timeout (int): DNS query timeout.
        allow_insecure (bool): Whether to allow insecure DoH requests.
        resolver (DoHResolver): DNS-over-HTTPS resolver instance.
        server_socket (socket.socket): Server socket listening for connections.
        executor (ThreadPoolExecutor): Thread pool for handling clients.
    """

    def __init__(self, config):
        """
        Initialize the proxy server with given configuration.

        Args:
            config (dict): Configuration dictionary.
        """
        self.host = config.get("proxy_host", "127.0.0.1")
        self.port = config.get("proxy_port", 4500)
        self.max_workers = config.get("max_workers", 50)
        self.dns_timeout = config.get("dns_timeout", 3)
        self.allow_insecure = config.get("allow_insecure", False)
        offline_dns_file = config.get("offline_dns_file")

        doh_urls = config.get("doh_urls", ["https://cloudflare-dns.com/dns-query?dns="])

        self.resolver = DoHResolver(
            doh_urls=doh_urls,
            offline_dns_file=offline_dns_file,
            allow_insecure=self.allow_insecure,
            dns_timeout=self.dns_timeout,
        )

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)

    def run(self):
        """
        Start the proxy server and accept incoming connections.
        """
        self.server_socket.listen(100)
        logger.info("[Proxy Server] Listening on %s:%d", self.host, self.port)

        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                client_socket.settimeout(10)
                logger.info("[Connection] Accepted from %s", addr)
                self.executor.submit(self.handle_client, client_socket)
        except KeyboardInterrupt:
            logger.info("Proxy server stopped by user")
        finally:
            self.server_socket.close()
            self.executor.shutdown(wait=True)

    def handle_client(self, client_socket):
        """
        Handle an individual client connection.

        Args:
            client_socket (socket.socket): Socket connected to client.
        """
        try:
            request = client_socket.recv(4096)
            if not request:
                client_socket.close()
                return

            if b"CONNECT" in request:
                host, port = self.extract_target_port(request)
                ip = self.resolver.resolve(host)

                if not ip:
                    logger.error("[DNS Failure] Could not resolve %s", host)
                    client_socket.close()
                    return

                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(10)
                server_socket.connect((ip, port))

                client_socket.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                logger.info("[Proxy] CONNECT %s:%d => %s", host, port, ip)

                self.forward(client_socket, server_socket)
            else:
                logger.info("[Proxy] Non-CONNECT request received. Closing.")
                client_socket.close()
        except (ConnectionError, OSError) as err:
            logger.error("[Error] Client handling failed: %s", err)
            client_socket.close()

    @staticmethod
    def extract_target_port(request):
        """
        Extract the target host and port from the CONNECT request line.

        Args:
            request (bytes): The raw request bytes from the client.

        Returns:
            tuple: (host (str), port (int))
        """
        line = request.decode(errors="ignore").split("\n")[0]
        target = line.split()[1]
        host, port = (target.split(":") + ["443"])[:2]
        return host, int(port)

    def forward(self, client, server):
        """
        Forward data bidirectionally between client and server sockets.

        Args:
            client (socket.socket): Client socket.
            server (socket.socket): Server socket.
        """
        threading.Thread(target=self._pipe, args=(client, server), daemon=True).start()
        threading.Thread(target=self._pipe, args=(server, client), daemon=True).start()

    @staticmethod
    def _pipe(src, dst):
        """
        Pipe data from src socket to dst socket until closed.

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
            # Silently close on connection errors
            pass
        finally:
            src.close()
            dst.close()


if __name__ == "__main__":
    import logging.config
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    try:
        with open("configs/config.json", "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as err:
        logging.error("Failed to load config.json: %s", err)
        config = {}

    server = ProxyServer(config)
    server.run()
