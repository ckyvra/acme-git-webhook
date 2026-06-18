from pydantic import BaseModel, ConfigDict, Field


_ACME_DOMAIN_PATTERN = (
    r"^_acme-challenge\."
    r"(\*\.)?"
    r"([a-zA-Z0-9_-]+\.)*"
    r"[a-zA-Z0-9-]+$"
)

_DOMAIN_PATTERN = (
    r"^(\*\.)?"
    r"([a-zA-Z0-9_-]+\.)*"
    r"[a-zA-Z0-9-]+$"
)


class AcmeRequest(BaseModel):
    """Request payload for ACME auth and cleanup endpoints.

    Sent by the ACME client (certbot, acme.sh, lego) when a DNS-01
    challenge needs to be provisioned or removed.

    Attributes:
        domain: The full domain being validated, including the
            _acme-challenge. prefix (e.g. _acme-challenge.example.com).
            The webhook strips the prefix internally to locate the
            correct Bind zone file.
        validation: The opaque token that must be inserted as a TXT
            record value. This field is required for auth requests and
            may be omitted for cleanup requests.
    """
    domain: str = Field(pattern=_ACME_DOMAIN_PATTERN)
    validation: str | None = Field(default=None, min_length=1, max_length=255)


class PropagationRequest(BaseModel):
    """Request payload for the DNS propagation check endpoint.

    Sent after ``/acme/auth`` to wait until the TXT record has
    propagated to all configured or provided nameservers. The endpoint
    polls until every server returns the expected validation token or
    the timeout is reached.

    Attributes:
        domain: The full ACME challenge domain including the
            ``_acme-challenge.`` prefix.
        validation: The expected TXT record value to wait for.
        nameservers: Optional list of nameserver IPs to query.
            Defaults to ``["8.8.8.8", "1.1.1.1"]`` when not provided.
        timeout: Maximum time in seconds to keep polling
            (default: 120).
        poll_interval: Seconds between each polling round
            (default: 5).
    """
    domain: str = Field(pattern=_ACME_DOMAIN_PATTERN)
    validation: str = Field(min_length=1, max_length=255)
    nameservers: list[str] | None = None
    timeout: int | None = None
    poll_interval: int | None = None


class CertDeployRequest(BaseModel):
    """Request payload for the certificate deployment endpoint.

    Called by the certbot deploy-hook after a successful renewal so
    that the webhook can store the certificate securely in Vault.

    The private key is a sensitive field: it is excluded from the
    model's string representation and from log output.

    Attributes:
        domain: The primary domain for the certificate (e.g.
            ``example.com``). For multi-domain certificates, this
            should be the first domain in the certificate.
        cert_pem: PEM-encoded leaf certificate.
        chain_pem: PEM-encoded intermediate chain (optional, may be
            empty for self-signed certs).
        fullchain_pem: PEM-encoded leaf certificate concatenated with
            the intermediate chain.
        privkey_pem: PEM-encoded private key. This value is never
            logged or included in the model's representation.
    """
    domain: str = Field(pattern=_DOMAIN_PATTERN)
    cert_pem: str
    chain_pem: str | None = None
    fullchain_pem: str
    privkey_pem: str

    model_config = ConfigDict(
        # Never include privkey_pem in model dumps used for logging.
        # See model_dump(exclude={"privkey_pem"}) in the endpoint.
    )

    def model_dump(self, *args, **kwargs):
        """Override to exclude privkey_pem by default for log safety."""
        if "exclude" not in kwargs:
            kwargs["exclude"] = {"privkey_pem"}
        return super().model_dump(*args, **kwargs)
