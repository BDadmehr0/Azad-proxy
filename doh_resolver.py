# pylint: disable=too-few-public-methods

"""
doh_resolver.py

A simple DNS-over-HTTPS (DoH) resolver using the requests and dnspython libraries.
Supports optional local overrides and caching of resolved addresses.
"""

import base64

import requests
from requests.exceptions import RequestException
import dns.message
import dns.rdatatype


class DoHResolver:
    """
    DNS-over-HTTPS resolver with support for local DNS overrides and caching.
    """

    def __init__(self, doh_url: str, offline_dns: dict, allow_insecure=False):
        """
        Initialize the DoH resolver.

        :param doh_url: Base URL of the DoH server (should end with `?dns=` for GET).
        :param offline_dns: A dictionary of domain-to-IP mappings for local overrides.
        :param allow_insecure: If True, disables SSL certificate verification (not recommended).
        """
        self.doh_url = doh_url
        self.offline_dns = offline_dns
        self.cache = {}
        self.session = requests.Session()
        self.allow_insecure = allow_insecure

    def resolve(self, domain: str) -> str:
        """
        Resolve the given domain name to an IPv4 address using DNS-over-HTTPS.

        :param domain: The domain name to resolve.
        :return: The resolved IP address as a string, or None if resolution fails.
        """
        if domain in self.offline_dns:
            return self.offline_dns[domain]

        if domain in self.cache:
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
                        return ip

        except (RequestException, dns.exception.DNSException) as e:
            print(f"[DoH Resolver] Failed to resolve {domain}: {e}")

        return None
