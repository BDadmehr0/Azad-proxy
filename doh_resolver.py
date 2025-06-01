"""
doh_resolver.py

A DNS-over-HTTPS (DoH) resolver with local fallback and cache.

✅ Encrypted DNS to avoid filtering/DPI.
✅ Supports internal/local DNS overrides (e.g., for in-country resolution).
"""

import base64

import dns.message
import dns.rdatatype
import requests
import urllib3
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DoHResolver:
    def __init__(self, doh_url: str, offline_dns: dict = None, allow_insecure=False):
        self.doh_url = doh_url
        self.offline_dns = offline_dns or {}
        self.cache = {}
        self.session = requests.Session()
        self.allow_insecure = allow_insecure

    def resolve(self, domain: str) -> str:
        if domain in self.offline_dns:
            ip = self.offline_dns[domain]
            print(f"[Offline DNS] {domain} => {ip}")
            return ip

        if domain in self.cache:
            print(f"[Cache] {domain} => {self.cache[domain]}")
            return self.cache[domain]

        try:
            query = dns.message.make_query(domain, "A")
            wire = query.to_wire()
            encoded = base64.urlsafe_b64encode(wire).decode("utf-8").rstrip("=")
            url = f"{self.doh_url}{encoded}"

            response = self.session.get(
                url,
                headers={"accept": "application/dns-message"},
                verify=not self.allow_insecure,
                timeout=3,
            )

            if response.status_code == 200:
                answer = dns.message.from_wire(response.content)
                for rrset in answer.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        ip = rrset[0].address
                        self.cache[domain] = ip
                        print(f"[DoH Resolver] {domain} => {ip}")
                        return ip
        except (RequestException, dns.exception.DNSException) as e:
            print(f"[DoH Error] Could not resolve {domain}: {e}")

        return None
