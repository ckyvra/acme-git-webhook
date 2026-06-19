from __future__ import annotations

import base64
import logging
from pathlib import Path

from app.config import ExchangeTargetConfig
from app.targets._crypto import pem_to_pfx
from app.targets.base import DeployResult, DeployTarget

logger = logging.getLogger(__name__)

try:
    import winrm
except ImportError:
    winrm = None  # type: ignore[assignment]


def _read_password(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise RuntimeError(f"Exchange password file not found: {path}")
    pw = p.read_text().strip()
    if not pw:
        raise RuntimeError(f"Exchange password file is empty: {path}")
    return pw


class ExchangeTarget(DeployTarget):
    """Deploy certificates to Exchange SMTP via WinRM and PowerShell.

    Converts the PEM certificate to PFX with a random password, copies
    it to the Exchange server via WinRM, then runs PowerShell cmdlets
    to import and enable it for the configured services (default: SMTP).
    """

    provider_type = "exchange"

    def __init__(self, config: ExchangeTargetConfig) -> None:
        self.name = config.name
        self.timeout = config.timeout
        self._config = config
        self._password: str | None = None

    def _ensure_winrm(self):
        if winrm is None:
            raise RuntimeError("pywinrm is not installed")
        if self._password is None:
            self._password = _read_password(self._config.password_path)

        transport = "ntlm" if self._config.transport == "ntlm" else "kerberos"
        return winrm.Session(
            self._config.addr,
            auth=(self._config.username, self._password),
            transport=transport,
            server_cert_validation="ignore" if not self._config.verify else "validate",
            operation_timeout_sec=self.timeout,
            read_timeout_sec=self.timeout + 30,
        )

    def deploy(
        self,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> DeployResult:
        try:
            session = self._ensure_winrm()
            pfx_bytes, password = pem_to_pfx(fullchain_pem, privkey_pem)
            pfx_b64 = base64.b64encode(pfx_bytes).decode()
            remote_file = f"{self._config.remote_path}\\{domain}.pfx"

            # Upload PFX via PowerShell base64 decode on the remote side
            upload_script = f'$bytes = [Convert]::FromBase64String("{pfx_b64}"); [IO.File]::WriteAllBytes("{remote_file}", $bytes)'
            r = session.run_ps(upload_script)
            if r.status_code != 0:
                raise RuntimeError(f"WinRM upload failed: {r.std_err.decode()}")

            # Import PFX and enable for configured services
            import_script = (
                f'$pwd = ConvertTo-SecureString "{password}" -AsPlainText -Force; '
                f'$cert = Import-ExchangeCertificate -FileName "{remote_file}" '
                f"-Password $pwd; "
                f"Enable-ExchangeCertificate -Thumbprint $cert.Thumbprint "
                f"-Services {self._config.services}"
            )
            r = session.run_ps(import_script)
            if r.status_code != 0:
                raise RuntimeError(f"WinRM import/enable failed: {r.std_err.decode()}")

            # Cleanup remote PFX
            cleanup_script = f'Remove-Item -Path "{remote_file}" -Force -ErrorAction SilentlyContinue'
            session.run_ps(cleanup_script)

            logger.info(
                "Exchange: deployed cert for %s services %s on %s",
                domain,
                self._config.services,
                self._config.addr,
            )
            return DeployResult(
                target=self.name,
                provider=self.provider_type,
                status="ok",
                details={
                    "host": self._config.addr,
                    "services": self._config.services,
                    "remote_path": remote_file,
                },
            )
        except Exception as e:
            logger.error("Exchange: deploy failed for %s: %s", domain, e)
            return DeployResult(
                target=self.name,
                provider=self.provider_type,
                status="error",
                error=str(e),
            )

    def close(self) -> None:
        pass
