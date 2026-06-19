from pathlib import Path

import dns.name
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.zone
from dns.rdtypes.txtbase import TXTBase


def _origin_from_zone_file(zone_file: Path) -> dns.name.Name:
    """Derive the DNS origin from the zone file name.

    Given a zone file path like ``/repo/zones/example.com.zone``,
    returns the dns.name.Name for ``example.com.``.

    Args:
        zone_file: Absolute path to the Bind zone file.

    Returns:
        A fully qualified dns name (ending with dot).
    """
    zone_name = zone_file.stem
    return dns.name.from_text(zone_name)


def _resolve_zone_path(
    repos_path: Path,
    domain: str,
    zone_path: str,
    suffix: str,
) -> Path | None:
    """Locate the Bind zone file for the given domain.

    The ACME client sends the full domain including the
    ``_acme-challenge.`` prefix. This method strips that prefix (and a
    leading ``*.`` if present for wildcard certs), then attempts to
    find a matching ``.zone`` file by trying progressively shorter
    domain suffixes.

    For example, ``_acme-challenge.sub.example.com`` first tries
    ``<zone_path>/sub.example.com.zone``, then
    ``<zone_path>/example.com.zone``, and returns the first match.
    This lets the same webhook serve domains that belong to different
    zones managed in the same repository.

    The resolved path is validated to stay within the allowed base
    directory as a defence-in-depth measure against path traversal
    attacks — even though the ``domain`` field is already validated
    by a Pydantic regex pattern in ``AcmeRequest``.

    Args:
        repos_path: Root of the cloned zone repository.
        domain: Full domain including ``_acme-challenge.`` prefix.
        zone_path: Subdirectory within the repo containing .zone files.
        suffix: File extension (e.g. ``.zone``).

    Returns:
        Absolute path to the zone file if found, None otherwise.
    """
    allowed_base = (repos_path / zone_path).resolve()
    clean = domain.removeprefix("_acme-challenge.").removeprefix("*.")
    labels = clean.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        path = repos_path / zone_path / f"{candidate}{suffix}"
        if path.exists():
            resolved = path.resolve()
            try:
                resolved.relative_to(allowed_base)
            except ValueError:
                continue
            return resolved
    return None


def add_txt_record(
    repos_path: Path,
    domain: str,
    token: str,
    zone_path: str,
    suffix: str,
) -> str:
    """Insert or replace the ``_acme-challenge.<domain>`` TXT record.

    Uses dnspython to parse the existing Bind zone file, clear any
    previous TXT record at the ACME challenge name, and add the new
    validation token. The zone file is then written back to disk in
    Bind text format.

    Only a single TXT value is kept per challenge name — this matches
    how most ACME clients and CAs work. If your workflow requires
    multiple simultaneous validations for the same domain name,
    the ``rdataset.add()`` logic should be extended to append rather
    than replace.

    Args:
        repos_path: Root of the cloned zone repository.
        domain: Full domain including ``_acme-challenge.`` prefix.
        token: The validation token to set as the TXT value.
        zone_path: Subdirectory within the repo containing .zone files.
        suffix: File extension for zone files.

    Returns:
        Absolute path to the modified zone file.

    Raises:
        FileNotFoundError: If no zone file could be resolved for the
            given domain.
    """
    zone_file = _resolve_zone_path(repos_path, domain, zone_path, suffix)
    if zone_file is None:
        raise FileNotFoundError(f"No zone file found for domain '{domain}' in {repos_path / zone_path}")

    origin = _origin_from_zone_file(zone_file)
    zone = dns.zone.from_file(str(zone_file), origin=origin)

    acme_name = dns.name.from_text(f"{domain}.")
    rdtype = dns.rdatatype.TXT
    rdclass = dns.rdataclass.IN

    rdataset = zone.get_rdataset(acme_name, rdtype)
    if rdataset is None:
        rdataset = dns.rdataset.Rdataset(rdclass, rdtype)
    else:
        rdataset.clear()

    rdataset.add(TXTBase(rdclass, rdtype, [token.encode()]))
    zone.replace_rdataset(acme_name, rdataset)
    zone.to_file(str(zone_file))
    return str(zone_file)


def remove_txt_record(
    repos_path: Path,
    domain: str,
    zone_path: str,
    suffix: str,
) -> str | None:
    """Remove the ``_acme-challenge.<domain>`` TXT record from the zone.

    Called during the cleanup phase of the ACME challenge after the CA
    has validated ownership and the certificate has been issued. The
    TXT record should be removed to keep the zone file clean.

    If no zone file matches the domain, or if the TXT record does not
    exist, the method returns None without error — this is intentional
    to make the webhook idempotent.

    Args:
        repos_path: Root of the cloned zone repository.
        domain: Full domain including ``_acme-challenge.`` prefix.
        zone_path: Subdirectory within the repo containing .zone files.
        suffix: File extension for zone files.

    Returns:
        Absolute path to the modified zone file if a record was
        removed, None if no matching zone file or TXT record was found.
    """
    zone_file = _resolve_zone_path(repos_path, domain, zone_path, suffix)
    if zone_file is None:
        return None

    origin = _origin_from_zone_file(zone_file)
    zone = dns.zone.from_file(str(zone_file), origin=origin)
    acme_name = dns.name.from_text(f"{domain}.")

    rdataset = zone.get_rdataset(acme_name, dns.rdatatype.TXT)
    if rdataset is None:
        return None
    zone.delete_rdataset(acme_name, dns.rdatatype.TXT)
    zone.to_file(str(zone_file))
    return str(zone_file)
