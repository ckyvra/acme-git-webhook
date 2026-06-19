from pathlib import Path
from textwrap import dedent

import pytest
from git import Repo

from app.config import AppConfig, AuthConfig, RepoConfig, WebhookConfig


def pytest_addoption(parser):
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests (require Docker, network, etc.)",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(reason="Use --run-integration to enable")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


@pytest.fixture
def sample_zone(tmp_path: Path) -> Path:
    src = Path(__file__).parent / "sample.zone"
    dst = tmp_path / "zones" / "example.com.zone"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(src.read_text())
    return dst


@pytest.fixture
def zone_content(sample_zone: Path) -> str:
    return sample_zone.read_text()


@pytest.fixture
def app_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        auth=AuthConfig(api_keys=["test-key-123"]),
        webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
        repo=RepoConfig(
            url="git@fake:org/dns-zones.git",
            branch="main",
            zone_path="zones",
            zone_file_suffix=".zone",
        ),
    )


@pytest.fixture
def bare_git_repo(tmp_path: Path) -> Path:
    bare = tmp_path / "remote.git"
    bare.mkdir(parents=True, exist_ok=True)
    Repo.init(str(bare), bare=True, initial_branch="main")

    clone_dir = tmp_path / "initial-clone"
    clone = Repo.clone_from(str(bare), str(clone_dir))
    zone_file = clone_dir / "zones" / "example.com.zone"
    zone_file.parent.mkdir(parents=True, exist_ok=True)
    zone_file.write_text(
        dedent("""\
            $TTL 3600
            @ IN SOA ns1.example.com. admin.example.com. (
                2024061701 ; serial
                3600       ; refresh
                900        ; retry
                604800     ; expire
                86400      ; minimum TTL
            )
            @ IN NS ns1.example.com.
            @ IN A 192.0.2.1
            www IN A 192.0.2.1
        """)
    )
    clone.index.add("*")
    clone.index.commit("Initial zone")
    clone.remotes.origin.push()

    return bare
