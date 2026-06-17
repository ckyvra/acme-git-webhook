import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.auth import verify_api_key


class TestVerifyApiKey:
    def test_valid_key(self):
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="my-key")
        result = verify_api_key(credentials=creds, valid_keys=["my-key"])
        assert result == "my-key"

    def test_invalid_key(self):
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong-key")
        with pytest.raises(HTTPException) as exc:
            verify_api_key(credentials=creds, valid_keys=["valid-key"])
        assert exc.value.status_code == 401

    def test_no_valid_keys_provided(self):
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="any")
        with pytest.raises(HTTPException) as exc:
            verify_api_key(credentials=creds, valid_keys=None)
        assert exc.value.status_code == 500

    def test_empty_valid_keys(self):
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="any")
        with pytest.raises(HTTPException) as exc:
            verify_api_key(credentials=creds, valid_keys=[])
        assert exc.value.status_code == 401
