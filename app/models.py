from pydantic import BaseModel


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
    domain: str
    validation: str | None = None
