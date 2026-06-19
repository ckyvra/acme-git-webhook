import ipaddress
import time

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver


def validate_nameserver(ip: str) -> bool:
    """Check that a nameserver IP is a valid, non-private address.

    Rejects loopback, private (RFC 1918), multicast, link-local,
    and unspecified addresses to prevent SSRF and DNS amplification
    attacks via the propagation endpoint.

    Args:
        ip: The IP address string to validate.

    Returns:
        True if the address is a valid global unicast IP, False
        otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_unspecified:
        return False
    return True


def _check_single_ns(
    qname: str,
    expected: str,
    nameserver: str,
) -> bool:
    """Query a single nameserver for a TXT record and compare with expected.

    Creates a temporary resolver pointed at the given nameserver, queries
    the TXT record for the absolute ACME challenge name, and checks if
    any of the returned strings match the expected validation token.

    Args:
        qname: Absolute DNS name to query (with trailing dot).
        expected: The expected TXT record value.
        nameserver: IP address of the nameserver to query.

    Returns:
        True if the nameserver returned at least one TXT record whose
        value matches ``expected``. Returns False on any error (timeout,
        NXDOMAIN, network error) or if the value does not match.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = 3
    resolver.lifetime = 3

    try:
        answer = resolver.resolve(qname, dns.rdatatype.TXT)
    except dns.exception.DNSException:
        # Any DNS error (NXDOMAIN, timeout, SERVFAIL) means the record
        # is not yet visible on this server — treat as pending.
        return False

    for rdata in answer:
        txt_value = b"".join(rdata.strings).decode()
        if txt_value == expected:
            return True
    return False


def check_propagation(
    domain: str,
    validation: str,
    nameservers: list[str],
    timeout: int,
    poll_interval: int = 5,
) -> dict:
    """Poll all given nameservers until every one returns the expected TXT.

    Builds the absolute ACME challenge name from the domain, then enters
    a polling loop. Each iteration queries every nameserver and collects
    which ones have the correct value. The loop exits early once all
    servers match.

    Args:
        domain: The full ACME challenge domain including the
            ``_acme-challenge.`` prefix.
        validation: The expected validation token.
        nameservers: List of nameserver IPs to query.
        timeout: Maximum total polling time in seconds.
        poll_interval: Seconds to wait between polling rounds.

    Returns:
        A dict with three keys:
            - ``matched``: nameservers that returned the expected value.
            - ``pending``: nameservers that never matched (empty on
              success).
            - ``elapsed``: total elapsed time in seconds.
    """
    # Build the absolute name once. The domain already includes the
    # _acme-challenge. prefix. Appending a trailing dot makes it
    # absolute so that the resolver does not append a search domain.
    qname = f"{domain}."
    elapsed = 0
    matched: list[str] = []
    pending: list[str] = list(nameservers)

    while elapsed < timeout:
        matched = []
        pending = []

        for ns in nameservers:
            if _check_single_ns(qname, validation, ns):
                matched.append(ns)
            else:
                pending.append(ns)

        if not pending:
            return {
                "matched": matched,
                "pending": [],
                "elapsed": elapsed,
            }

        time.sleep(poll_interval)
        elapsed += poll_interval

    # Timeout reached — return whatever state we have.
    return {
        "matched": matched,
        "pending": pending,
        "elapsed": timeout,
    }
