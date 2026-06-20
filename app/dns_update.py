import logging
from pathlib import Path

import dns.name
import dns.query
import dns.tsigkeyring
import dns.update
from dns.rdatatype import TXT

logger = logging.getLogger(__name__)


def _build_keyring(key_name: str, secret: str, algorithm: str) -> dict:
    return {key_name: {"secret": secret, "algorithm": algorithm}}


def _normalize_zone(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    return ".".join(parts[1:]) + "."


def add_txt_record(
    domain: str,
    value: str,
    server: str = "127.0.0.1",
    port: int = 53,
    key_name: str = "acme-key.",
    key_secret: str | None = None,
    key_file: str | Path | None = None,
    key_algorithm: str = "hmac-sha256",
    zone: str | None = None,
    ttl: int = 60,
) -> None:
    zone_name = zone if zone else _normalize_zone(domain)
    fqdn = f"_acme-challenge.{domain}."

    secret = key_secret
    if not secret and key_file:
        secret = Path(key_file).read_text().strip()

    if not secret:
        raise ValueError("Either key_secret or key_file must be provided")

    keyring = _build_keyring(key_name, secret, key_algorithm)

    update = dns.update.Update(
        dns.name.from_text(zone_name),
        keyring=keyring if secret else None,
        keyname=dns.name.from_text(key_name) if key_name else None,
        keyalgorithm=key_algorithm,
    )

    update.replace(fqdn, ttl, TXT, value)

    response = dns.query.tcp(update, server, port=port, timeout=10)
    if response.rcode() != 0:
        raise RuntimeError(f"nsupdate failed with rcode {response.rcode()}")
    logger.info("Added TXT record for %s via nsupdate (rcode=%d)", domain, response.rcode())


def remove_txt_record(
    domain: str,
    server: str = "127.0.0.1",
    port: int = 53,
    key_name: str = "acme-key.",
    key_secret: str | None = None,
    key_file: str | Path | None = None,
    key_algorithm: str = "hmac-sha256",
    zone: str | None = None,
) -> bool:
    zone_name = zone if zone else _normalize_zone(domain)
    fqdn = f"_acme-challenge.{domain}."

    secret = key_secret
    if not secret and key_file:
        secret = Path(key_file).read_text().strip()

    if not secret:
        raise ValueError("Either key_secret or key_file must be provided")

    keyring = _build_keyring(key_name, secret, key_algorithm)

    update = dns.update.Update(
        dns.name.from_text(zone_name),
        keyring=keyring if secret else None,
        keyname=dns.name.from_text(key_name) if key_name else None,
        keyalgorithm=key_algorithm,
    )

    update.delete(fqdn, TXT)

    try:
        response = dns.query.tcp(update, server, port=port, timeout=10)
        if response.rcode() != 0:
            raise RuntimeError(f"nsupdate failed with rcode {response.rcode()}")
        logger.info("Removed TXT record for %s via nsupdate (rcode=%d)", domain, response.rcode())
        return True
    except Exception:
        logger.exception("Failed to remove TXT record for %s via nsupdate", domain)
        return False
