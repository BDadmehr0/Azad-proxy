"""
proxy_server.py

A censorship-resistant HTTPS proxy server that uses DNS over HTTPS (DoH)
for DNS resolution.

Suitable for environments with strong censorship or Deep Packet Inspection (DPI).
Compatible with custom or internal DNS mappings (e.g., local networks or Iran-specific).
"""

import socket
import threading
import time

from doh_resolver import DoHResolver


class ProxyServer:
    """
    A simple multi-threaded HTTPS proxy server with DoH-based DNS resolution.
    """

    def __init__(self, host="127.0.0.1", port=4500):
        self.host = host
        self.port = port

        self.resolver = DoHResolver(
            doh_url="https://cloudflare-dns.com/dns-query?dns=",
            offline_dns={
                "cloudflare-dns.com": "203.32.120.226",
                "dns.google": "8.8.8.8",  # IP filtered
                "doh.opendns.com": "208.67.222.222",
                "secure.avastdns.com": "185.185.133.66",
                "doh.libredns.gr": "116.202.176.26",
                "dns.electrotm.org": "78.157.42.100",
                "dns.bitdefender.net": "34.84.232.67",
                "cluster-1.gac.edu": "138.236.128.101",
                "api.twitter.com": "104.244.42.66",
                "twitter.com": "104.244.42.1",
                "pbs.twimg.com": "93.184.220.70",
                "abs-0.twimg.com": "104.244.43.131",
                "abs.twimg.com": "152.199.24.185",
                "video.twimg.com": "192.229.220.133",
                "t.co": "104.244.42.69",
                "ton.local.twitter.com": "104.244.42.1",
                "instagram.com": "163.70.128.174",
                "www.instagram.com": "163.70.128.174",
                "static.cdninstagram.com": "163.70.132.63",
                "scontent.cdninstagram.com": "163.70.132.63",
                "privacycenter.instagram.com": "163.70.128.174",
                "help.instagram.com": "163.70.128.174",
                "l.instagram.com": "163.70.128.174",
                "e1.whatsapp.net": "163.70.128.60",
                "e2.whatsapp.net": "163.70.128.60",
                "e3.whatsapp.net": "163.70.128.60",
                "e4.whatsapp.net": "163.70.128.60",
                "e5.whatsapp.net": "163.70.128.60",
                "e6.whatsapp.net": "163.70.128.60",
                "e7.whatsapp.net": "163.70.128.60",
                "e8.whatsapp.net": "163.70.128.60",
                "e9.whatsapp.net": "163.70.128.60",
                "e10.whatsapp.net": "163.70.128.60",
                "e11.whatsapp.net": "163.70.128.60",
                "e12.whatsapp.net": "163.70.128.60",
                "e13.whatsapp.net": "163.70.128.60",
                "e14.whatsapp.net": "163.70.128.60",
                "e15.whatsapp.net": "163.70.128.60",
                "e16.whatsapp.net": "163.70.128.60",
                "dit.whatsapp.net": "185.60.219.60",
                "g.whatsapp.net": "185.60.218.54",
                "wa.me": "185.60.219.60",
                "web.whatsapp.com": "31.13.83.51",
                "whatsapp.net": "31.13.83.51",
                "whatsapp.com": "31.13.83.51",
                "cdn.whatsapp.net": "31.13.83.51",
                "snr.whatsapp.net": "31.13.83.51",
                "static.xx.fbcdn.net": "31.13.75.13",
                "scontent-mct1-1.xx.fbcdn.net": "31.13.75.13",
                "video-mct1-1.xx.fbcdn.net": "31.13.75.13",
                "video.fevn1-2.fna.fbcdn.net": "185.48.241.146",
                "video.fevn1-4.fna.fbcdn.net": "185.48.243.145",
                "scontent.xx.fbcdn.net": "185.48.240.146",
                "scontent.fevn1-1.fna.fbcdn.net": "185.48.240.145",
                "scontent.fevn1-2.fna.fbcdn.net": "185.48.241.145",
                "scontent.fevn1-3.fna.fbcdn.net": "185.48.242.146",
                "scontent.fevn1-4.fna.fbcdn.net": "185.48.243.147",
                "connect.facebook.net": "31.13.84.51",
                "facebook.com": "31.13.65.49",
                "developers.facebook.com": "31.13.84.8",
                "about.meta.com": "163.70.128.13",
                "meta.com": "163.70.128.13",
                "ocsp.pki.goog": "172.217.16.195",
                "googleads.g.doubleclick.net": "45.157.177.108",
                "fonts.gstatic.com": "142.250.185.227",
                "rr2---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.141",
                "jnn-pa.googleapis.com": "45.157.177.108",
                "static.doubleclick.net": "202.61.195.218",
                "rr4---sn-hju7en7k.googlevideo.com": "74.125.167.74",
                "rr1---sn-hju7en7r.googlevideo.com": "74.125.167.87",
                "play.google.com": "142.250.184.238",
                "rr3---sn-vh5ouxa-hjuz.googlevideo.com": "134.0.218.206",
                "rr3---sn-hju7enel.googlevideo.com": "74.125.98.40",
                "download.visualstudio.microsoft.com": "68.232.34.200",
                "ocsp.pki.goog": "172.217.16.195",
                "i.ytimg.com": "142.250.186.150",
                "rr2---sn-hju7enel.googlevideo.com": "74.125.98.39",
                "rr2---sn-hju7en7k.googlevideo.com": "74.125.167.72",
                "googleads.g.doubleclick.net": "45.157.177.108",
                "rr3---sn-4g5lznl6.googlevideo.com": "74.125.173.40",
                "jnn-pa.googleapis.com": "89.58.57.45",
                "rr3---sn-hju7en7k.googlevideo.com": "74.125.167.73",
                "rr1---sn-hju7enll.googlevideo.com": "74.125.98.6",
                "rr6---sn-hju7en7r.googlevideo.com": "74.125.167.92",
                "play.google.com": "216.58.212.174",
                "www.gstatic.com": "142.250.185.99",
                "apis.google.com": "172.217.23.110",
                "adservice.google.com": "202.61.195.218",
                "mail.google.com": "142.250.186.37",
                "accounts.google.com": "172.217.16.205",
                "lh3.googleusercontent.com": "193.26.157.66",
                "accounts.youtube.com": "172.217.16.206",
                "ssl.gstatic.com": "142.250.184.195",
                "fonts.gstatic.com": "172.217.23.99",
                "rr4---sn-hju7enll.googlevideo.com": "74.125.98.9",
                "rr2---sn-hju7enll.googlevideo.com": "74.125.98.7",
                "rr1---sn-hju7enel.googlevideo.com": "74.125.98.38",
                "rr5---sn-vh5ouxa-hjuz.googlevideo.com": "134.0.218.208",
                "i1.ytimg.com": "172.217.18.14",
                "plos.org": "162.159.135.42",
                "fonts.googleapis.com": "89.58.57.45",
                "genweb.plos.org": "104.26.1.141",
                "static.ads-twitter.com": "146.75.120.157",
                "www.google-analytics.com": "142.250.185.174",
                "rr1---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.140",
                "rr5---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.144",
                "rr3---sn-hju7enel.googlevideo.com": "74.125.98.40",
                "rr5---sn-nv47zn7y.googlevideo.com": "173.194.15.74",
                "rr1---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.140",
                "safebrowsing.googleapis.com": "202.61.195.218",
                "static.doubleclick.net": "193.26.157.66",
                "rr5---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.144",
                "rr1---sn-hju7en7r.googlevideo.com": "74.125.167.87",
                "rr4---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.143",
                "rr4---sn-hju7en7r.googlevideo.com": "74.125.167.90",
                "r1---sn-hju7enel.googlevideo.com": "74.125.98.38",
                "rr1---sn-nv47zn7r.googlevideo.com": "173.194.15.38",
                "rr2---sn-vh5ouxa-hjuz.googlevideo.com": "134.0.218.205",
                "rr4---sn-nv47zn7r.googlevideo.com": "173.194.15.41",
                "rr4---sn-hju7en7r.googlevideo.com": "74.125.167.90",
                "www.google.com": "142.250.186.36",
                "youtube.com": "216.239.38.120",
                "youtu.be": "216.239.38.120",
                "www.youtube.com": "216.239.38.120",
                "i.ytimg.com": "216.239.38.120",
                "yt3.ggpht.com": "142.250.186.36",  # most of times work
            },
            allow_insecure=True,
        )

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))

    def run(self):
        self.server_socket.listen(100)
        print(f"[Proxy Server] Listening on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.server_socket.accept()
            client_socket.settimeout(10)
            print(f"[Connection] Accepted from {addr}")
            threading.Thread(
                target=self.handle_client, args=(client_socket,), daemon=True
            ).start()

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096)
            if not request:
                client_socket.close()
                return

            if b"CONNECT" in request:
                host, port = self.extract_target_port(request)
                ip = self.resolver.resolve(host)

                if not ip:
                    print(f"[DNS Failure] Could not resolve {host}")
                    client_socket.close()
                    return

                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(10)
                server_socket.connect((ip, port))

                client_socket.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                print(f"[Proxy] CONNECT {host}:{port} => {ip}")

                self.forward(client_socket, server_socket)
            else:
                print("[Proxy] Non-CONNECT request received. Closing.")
                client_socket.close()
        except Exception as e:
            print(f"[Error] Client handling failed: {e}")
            client_socket.close()

    def extract_target_port(self, request):
        line = request.decode(errors="ignore").split("\n")[0]
        target = line.split()[1]
        host, port = (target.split(":") + ["443"])[:2]
        return host, int(port)

    def forward(self, client, server):
        threading.Thread(target=self._pipe, args=(client, server), daemon=True).start()
        threading.Thread(target=self._pipe, args=(server, client), daemon=True).start()

    def _pipe(self, src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            src.close()
            dst.close()


if __name__ == "__main__":
    ProxyServer().run()
