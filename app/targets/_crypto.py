from __future__ import annotations

import secrets
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12PrivateKeyTypes


def pem_to_pfx(fullchain_pem: str, privkey_pem: str) -> tuple[bytes, str]:
    """Convert PEM fullchain + private key to PKCS12 (PFX) bytes.

    Returns:
        Tuple of (pfx_bytes, random_password).
    """
    password = secrets.token_urlsafe(24)

    private_key = cast(PKCS12PrivateKeyTypes, serialization.load_pem_private_key(privkey_pem.encode(), password=None))
    fullchain = x509.load_pem_x509_certificates(fullchain_pem.encode())

    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=b"acme-deploy",
        key=private_key,
        cert=fullchain[0],
        cas=fullchain[1:] or None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    return pfx_bytes, password
