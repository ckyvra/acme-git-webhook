import os
from pathlib import Path

import yaml
from pydantic import BaseModel


class AuthConfig(BaseModel):
    """Authentication configuration.

    Attributes:
        api_keys: List of accepted Bearer tokens. Any client request
            carrying one of these keys in the Authorization header will
            be allowed to trigger add/remove operations.
    """
    api_keys: list[str]


class WebhookConfig(BaseModel):
    """Webhook server configuration.

    Attributes:
        bind: Host and port the FastAPI server listens on
            (default: 0.0.0.0:8000).
        work_dir: Local directory used for cloning the zone repository
            and storing the inter-process lock file.
        ssh_key: Path to a deploy SSH key (mounted file or secret).
            When set, GitPython is configured to use this key for
            authentication instead of the default SSH agent.
    """
    bind: str = "0.0.0.0:8000"
    work_dir: str = "/data/acme-git-webhook"
    ssh_key: str | None = None


class RepoConfig(BaseModel):
    """Git repository layout for Bind zone files.

    Attributes:
        url: SSH or HTTPS remote URL of the zone repository.
        branch: Git branch to clone and push to (default: main).
        zone_path: Subdirectory within the repo where .zone files
            are stored (e.g. "zones"). Use "." for the repo root.
        zone_file_suffix: File extension of Bind zone files
            (default: .zone).
    """
    url: str
    branch: str = "main"
    zone_path: str = "."
    zone_file_suffix: str = ".zone"


class AppConfig(BaseModel):
    """Top-level application configuration.

    Groups authentication, webhook server and repository settings
    into a single validated object loaded from config.yaml.
    """
    auth: AuthConfig
    webhook: WebhookConfig
    repo: RepoConfig


def load_config(path: str | None = None) -> AppConfig:
    """Load and validate the YAML configuration file.

    Resolves the config path from the CONFIG_PATH environment variable
    first, then falls back to "config.yaml" in the working directory.

    Args:
        path: Optional explicit path to the configuration file.
            If None, the environment variable or default is used.

    Returns:
        A validated AppConfig instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        pydantic.ValidationError: If the YAML content does not match
            the expected schema.
    """
    if path is None:
        path = os.getenv("CONFIG_PATH", "config.yaml")
    with open(path) as f:
        data = yaml.safe_load(f)
    return AppConfig.model_validate(data)
