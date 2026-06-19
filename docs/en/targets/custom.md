# Custom deploy target

You can extend the webhook with your own deployment targets by implementing the `DeployTarget` abstract base class and registering it in the manager.

## The `DeployTarget` interface

All targets live in `app/targets/`. The base class is defined in `app/targets/base.py`:

```python
from abc import ABC, abstractmethod


class DeployResult(BaseModel):
    target: str
    provider: str
    status: Literal["ok", "error"]
    details: dict = {}
    error: str | None = None


class DeployTarget(ABC):
    name: str
    provider_type: str
    timeout: int

    @abstractmethod
    def deploy(
        self,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> DeployResult:
        ...

    def close(self) -> None:
        """Release any held resources (HTTP clients, etc.)."""
```

## Step 1: Create the target class

```python
# app/targets/myappliance.py
import logging

import httpx

from app.config import BaseModel  # or use any Pydantic model
from app.targets.base import DeployResult, DeployTarget

logger = logging.getLogger(__name__)


class MyApplianceConfig(BaseModel):
    name: str
    provider: str = "myappliance"
    addr: str
    api_key_path: str
    verify: bool = True
    timeout: int = 60


class MyApplianceTarget(DeployTarget):
    provider_type = "myappliance"

    def __init__(self, config: MyApplianceConfig) -> None:
        self.name = config.name
        self.timeout = config.timeout
        self._config = config
        self._client: httpx.Client | None = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            api_key = Path(self._config.api_key_path).read_text().strip()
            self._client = httpx.Client(
                base_url=self._config.addr,
                headers={"Authorization": f"Bearer {api_key}"},
                verify=self._config.verify,
                timeout=self.timeout,
            )
        return self._client

    def deploy(
        self,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> DeployResult:
        try:
            client = self._ensure_client()
            payload = {"domain": domain, "cert": fullchain_pem, "key": privkey_pem}
            r = client.post("/api/deploy", json=payload)
            r.raise_for_status()
            return DeployResult(
                target=self.name,
                provider=self.provider_type,
                status="ok",
                details={"host": self._config.addr},
            )
        except Exception as e:
            logger.error("MyAppliance deploy failed: %s", e)
            return DeployResult(
                target=self.name,
                provider=self.provider_type,
                status="error",
                error=str(e),
            )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
```

## Step 2: Add the config model

Add your config to the `TargetConfig` discriminated union in `app/config.py`:

```python
from typing import Annotated, Union
from pydantic import Field

TargetConfig = Annotated[
    Union[
        F5TargetConfig,
        IvantiTargetConfig,
        ExchangeTargetConfig,
        MyApplianceConfig,  # <-- add yours
    ],
    Field(discriminator="provider"),
]
```

## Step 3: Register in the manager

Add a branch in `_build_target()` in `app/targets/manager.py`:

```python
def _build_target(cfg: TargetConfig) -> DeployTarget:
    if cfg.provider == "f5":
        from app.targets.f5 import F5Target
        return F5Target(cfg)
    if cfg.provider == "ivanti":
        from app.targets.ivanti import IvantiTarget
        return IvantiTarget(cfg)
    if cfg.provider == "exchange":
        from app.targets.exchange import ExchangeTarget
        return ExchangeTarget(cfg)
    if cfg.provider == "myappliance":       # <--
        from app.targets.myappliance import MyApplianceTarget
        return MyApplianceTarget(cfg)
    msg = f"Unknown target provider: {cfg.provider}"
    raise ValueError(msg)
```

## Step 4: Configure in `config.yaml`

```yaml
targets:
  - name: "my-appliance"
    provider: "myappliance"
    addr: "https://appliance.example.com"
    api_key_path: "/run/secrets/appliance_api_key"
```

## Design guidelines

- **Fail fast** — catch exceptions in `deploy()` and return a `DeployResult` with `status="error"` rather than letting them propagate.
- **Secrets from files** — never embed passwords or API keys in the config YAML. Always read from a mounted file path.
- **Idempotency** — multiple deployments for the same domain should be safe to repeat.
- **Timeout** — always pass `timeout=self.timeout` to HTTP clients.
- **Close resources** — implement `close()` to clean up HTTP clients, sessions, etc.
