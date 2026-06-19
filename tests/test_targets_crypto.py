from cryptography.hazmat.primitives.serialization import pkcs12

from app.targets._crypto import pem_to_pfx
from tests.cert_helper import generate_self_signed_cert


class TestPemToPfx:
    def test_returns_bytes_and_password(self):
        cert_pem, key_pem = generate_self_signed_cert()
        pfx_bytes, password = pem_to_pfx(cert_pem, key_pem)
        assert isinstance(pfx_bytes, bytes)
        assert len(pfx_bytes) > 0
        assert isinstance(password, str)
        assert len(password) > 0

    def test_pfx_can_be_loaded_back(self):
        cert_pem, key_pem = generate_self_signed_cert()
        pfx_bytes, password = pem_to_pfx(cert_pem, key_pem)

        loaded = pkcs12.load_key_and_certificates(pfx_bytes, password.encode())
        loaded_key, loaded_cert, loaded_cas = loaded

        assert loaded_key is not None
        assert loaded_cert is not None
        assert loaded_cas == []

    def test_with_chain_cas(self):
        cert_pem, key_pem = generate_self_signed_cert()
        ca_pem, ca_key = generate_self_signed_cert("ca.example.com")
        fullchain = cert_pem + "\n" + ca_pem

        pfx_bytes, password = pem_to_pfx(fullchain, key_pem)

        loaded = pkcs12.load_key_and_certificates(pfx_bytes, password.encode())
        loaded_key, loaded_cert, loaded_cas = loaded

        assert loaded_key is not None
        assert loaded_cert is not None
        assert len(loaded_cas) == 1

    def test_password_varies_each_call(self):
        cert_pem, key_pem = generate_self_signed_cert()
        _, pwd1 = pem_to_pfx(cert_pem, key_pem)
        _, pwd2 = pem_to_pfx(cert_pem, key_pem)
        assert pwd1 != pwd2
