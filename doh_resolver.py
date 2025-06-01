"""
Module for DNS-over-HTTPS (DoH) resolution with caching, retries, and offline fallback.
"""

import base64
import json
import logging
import random
import time

import dns.message
import dns.rdatatype
import requests
import urllib3
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("DoHResolver")


class DoHResolver:
    """
    Resolver class to query DNS-over-HTTPS servers with caching,
    retry, backoff, and offline DNS fallback.
    """

    def __init__(
        self,
        doh_urls,
        offline_dns_file=None,
        allow_insecure=False,
        dns_timeout=3,
        max_retries=3,
    ):
        """
        Initialize the resolver.

        Args:
            doh_urls (list): List of DoH server URLs (with '?dns=' suffix).
            offline_dns_file (str): Path to offline DNS JSON file.
            allow_insecure (bool): Whether to allow insecure HTTPS connections.
            dns_timeout (int): Timeout in seconds for DoH requests.
            max_retries (int): Maximum number of retries on failure.
        """
        self.doh_urls = doh_urls
        self.allow_insecure = allow_insecure
        self.dns_timeout = dns_timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.cache = {}  # domain -> (ip, expire_time)

        if offline_dns_file:
            try:
                with open(offline_dns_file, "r", encoding="utf-8") as f:
                    self.offline_dns = json.load(f)
                logger.info("Loaded offline DNS from %s", offline_dns_file)
            except (OSError, json.JSONDecodeError) as err:
                logger.error(
                    "Failed to load offline DNS file %s: %s", offline_dns_file, err
                )
                self.offline_dns = {}
        else:
            self.offline_dns = {}

    def resolve(self, domain: str) -> str:
        """
        Resolve domain to IP address using cache, offline DNS, and DoH servers.

        Args:
            domain (str): The domain name to resolve.

        Returns:
            str: Resolved IP address or None if resolution fails.
        """
        now = time.time()

        # Check cache
        cached = self.cache.get(domain)
        if cached:
            ip, expire = cached
            if expire > now:
                logger.debug("[Cache] %s => %s", domain, ip)
                return ip
            logger.debug("[Cache Expired] %s", domain)
            del self.cache[domain]

        # Check offline DNS
        ip = self.offline_dns.get(domain)
        if ip:
            logger.info("[Offline DNS] %s => %s", domain, ip)
            return ip

        # Try DoH servers with retries and backoff
        for attempt in range(self.max_retries):
            doh_urls_shuffled = random.sample(self.doh_urls, len(self.doh_urls))
            for doh_url in doh_urls_shuffled:
                ip = self._query_doh(domain, doh_url)
                if ip:
                    return ip

            backoff = 0.5 * (2**attempt)
            logger.warning("Retrying %s after %.1f seconds", domain, backoff)
            time.sleep(backoff)

        logger.error("[DoH Error] Could not resolve %s after retries", domain)
        return None

    def _query_doh(self, domain, doh_url):
        """
        Query a single DoH server.

        Args:
            domain (str): Domain to resolve.
            doh_url (str): DoH server URL prefix.

        Returns:
            str: IP address if resolved, else None.
        """
        try:
            query = dns.message.make_query(domain, "A")
            wire = query.to_wire()
            encoded = base64.urlsafe_b64encode(wire).decode("utf-8").rstrip("=")
            url = doh_url + encoded

            response = self.session.get(
                url,
                headers={"accept": "application/dns-message"},
                verify=not self.allow_insecure,
                timeout=self.dns_timeout,
            )

            if response.status_code == 200:
                answer = dns.message.from_wire(response.content)
                for rrset in answer.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        ip = rrset[0].address
                        ttl = getattr(rrset, "ttl", 60)
                        expire_time = time.time() + ttl
                        self.cache[domain] = (ip, expire_time)
                        logger.info(
                            "[DoH Resolver] %s => %s (TTL: %d) from %s",
                            domain,
                            ip,
                            ttl,
                            doh_url,
                        )
                        return ip
        except (RequestException, dns.exception.DNSException) as err:
            logger.warning("[DoH Query Error] %s on %s: %s", domain, doh_url, err)
        return None
