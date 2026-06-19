import pytest
import yaml
from pydantic import ValidationError

from app.config import (
    AppConfig,
    AuthConfig,
    MonitorConfig,
    OpensslConfig,
    PostQuantumConfig,
    RepoConfig,
    VaultConfig,
    WebhookConfig,
    load_config,
)


class TestAuthConfig:
    def test_valid(self):
        cfg = AuthConfig(api_keys=["key1", "key2"])
        assert cfg.api_keys == ["key1", "key2"]

    def test_empty_keys(self):
        cfg = AuthConfig(api_keys=[])
        assert cfg.api_keys == []


class TestWebhookConfig:
    def test_defaults(self):
        cfg = WebhookConfig()
        assert cfg.bind == "0.0.0.0:8000"
        assert cfg.work_dir == "/data/acme-git-webhook"
        assert cfg.ssh_key is None
        assert cfg.known_hosts_path is None

    def test_custom(self):
        cfg = WebhookConfig(
            bind="127.0.0.1:9000",
            work_dir="/tmp/test",
            ssh_key="/key",
            known_hosts_path="/run/secrets/known_hosts",
        )
        assert cfg.bind == "127.0.0.1:9000"
        assert cfg.ssh_key == "/key"
        assert cfg.known_hosts_path == "/run/secrets/known_hosts"


class TestRepoConfig:
    def test_defaults(self):
        cfg = RepoConfig(url="git@github.com:org/dns-zones.git")
        assert cfg.branch == "main"
        assert cfg.zone_path == "."
        assert cfg.zone_file_suffix == ".zone"

    def test_custom(self):
        cfg = RepoConfig(
            url="git@example.com:repo.git",
            branch="develop",
            zone_path="bind/zones",
            zone_file_suffix=".db",
        )
        assert cfg.zone_path == "bind/zones"
        assert cfg.zone_file_suffix == ".db"


class TestAppConfig:
    def test_valid(self):
        cfg = AppConfig(
            auth=AuthConfig(api_keys=["k"]),
            webhook=WebhookConfig(),
            repo=RepoConfig(url="git@github.com:org/dns-zones.git"),
        )
        assert cfg.auth.api_keys == ["k"]

    def test_missing_field(self):
        with pytest.raises(ValidationError):
            AppConfig(auth=AuthConfig(api_keys=["k"]), webhook=WebhookConfig())


class TestLoadConfig:
    def test_load_valid(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump(
                {
                    "auth": {"api_keys": ["sk-test"]},
                    "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                    "repo": {"url": "git@github.com:org/dns-zones.git"},
                }
            )
        )
        cfg = load_config(str(path))
        assert cfg.auth.api_keys == ["sk-test"]
        assert cfg.repo.url == "git@github.com:org/dns-zones.git"

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_invalid_yaml(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("auth: {bad_yaml: ")
        with pytest.raises(yaml.YAMLError):
            load_config(str(path))

    def test_missing_required_field(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump({"auth": {"api_keys": ["k"]}}))
        with pytest.raises(ValidationError):
            load_config(str(path))

    def test_with_vault_section(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump(
                {
                    "auth": {"api_keys": ["sk-test"]},
                    "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                    "repo": {"url": "git@github.com:org/dns-zones.git"},
                    "vault": {
                        "addr": "https://vault.example.com:8200",
                        "role_id": "role-abc",
                        "secret_id_path": "/run/secrets/vault_secret_id",
                    },
                }
            )
        )
        cfg = load_config(str(path))
        assert cfg.vault is not None
        assert cfg.vault.addr == "https://vault.example.com:8200"
        assert cfg.vault.role_id == "role-abc"
        assert cfg.vault.kv_mount == "secret"

    def test_without_vault_section(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump(
                {
                    "auth": {"api_keys": ["sk-test"]},
                    "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                    "repo": {"url": "git@github.com:org/dns-zones.git"},
                }
            )
        )
        cfg = load_config(str(path))
        assert cfg.vault is None

    def test_load_with_default_path(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            yaml.dump(
                {
                    "auth": {"api_keys": ["sk-test"]},
                    "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                    "repo": {"url": "git@github.com:org/dns-zones.git"},
                }
            )
        )
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg.auth.api_keys == ["sk-test"]

    def test_load_vault_with_verify_false_warns(self, tmp_path, caplog):
        import logging

        caplog.set_level(logging.WARNING)
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump(
                {
                    "auth": {"api_keys": ["sk-test"]},
                    "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                    "repo": {"url": "git@github.com:org/dns-zones.git"},
                    "vault": {
                        "addr": "https://vault.example.com:8200",
                        "role_id": "role-abc",
                        "secret_id_path": "/run/secrets/vault_secret_id",
                        "verify": False,
                    },
                }
            )
        )
        cfg = load_config(str(path))
        assert cfg.vault.verify is False
        assert "Vault TLS verification is DISABLED" in caplog.text


class TestVaultConfig:
    def test_valid(self):
        cfg = VaultConfig(
            addr="https://vault.example.com:8200",
            role_id="role-abc",
            secret_id_path="/secrets/vault_secret_id",
        )
        assert cfg.addr == "https://vault.example.com:8200"
        assert cfg.role_id == "role-abc"
        assert cfg.kv_mount == "secret"
        assert cfg.certs_path == "certs"
        assert cfg.verify is True
        assert cfg.skip is False

    def test_custom_values(self):
        cfg = VaultConfig(
            addr="http://127.0.0.1:8200",
            role_id="role-xyz",
            secret_id_path="/tmp/secret",
            kv_mount="kv-v2",
            certs_path="pki/certs",
            verify=False,
            skip=True,
        )
        assert cfg.kv_mount == "kv-v2"
        assert cfg.certs_path == "pki/certs"
        assert cfg.verify is False
        assert cfg.skip is True

    def test_missing_required(self):
        with pytest.raises(ValidationError):
            VaultConfig(addr="https://vault.example.com:8200")

    def test_skip_defaults_to_false(self):
        cfg = VaultConfig(
            addr="https://vault.example.com:8200",
            role_id="role-abc",
            secret_id_path="/secrets/id",
        )
        assert cfg.skip is False


class TestOpensslConfig:
    def test_defaults(self):
        cfg = OpensslConfig()
        assert cfg.key_algorithm == "ecdsa"
        assert cfg.rsa_key_size == 4096
        assert cfg.ecdsa_curve == "secp384r1"
        assert cfg.signature_hash == "sha384"
        assert cfg.post_quantum is None

    def test_rsa_algorithm(self):
        cfg = OpensslConfig(key_algorithm="rsa", rsa_key_size=2048)
        assert cfg.key_algorithm == "rsa"
        assert cfg.rsa_key_size == 2048

    def test_ed25519_algorithm(self):
        cfg = OpensslConfig(key_algorithm="ed25519")
        assert cfg.key_algorithm == "ed25519"

    def test_ecdsa_curve_options(self):
        for curve in ("secp256r1", "secp384r1", "secp521r1"):
            cfg = OpensslConfig(ecdsa_curve=curve)
            assert cfg.ecdsa_curve == curve

    def test_signature_hash_options(self):
        for h in ("sha256", "sha384", "sha512"):
            cfg = OpensslConfig(signature_hash=h)
            assert cfg.signature_hash == h

    def test_invalid_key_algorithm(self):
        with pytest.raises(ValidationError):
            OpensslConfig(key_algorithm="dsa")

    def test_invalid_curve(self):
        with pytest.raises(ValidationError):
            OpensslConfig(ecdsa_curve="secp192r1")

    def test_post_quantum_subsection(self):
        cfg = OpensslConfig(post_quantum=PostQuantumConfig(enabled=True, hybrid_mode=False))
        assert cfg.post_quantum is not None
        assert cfg.post_quantum.enabled is True
        assert cfg.post_quantum.hybrid_mode is False

    def test_post_quantum_defaults(self):
        cfg = OpensslConfig(post_quantum=PostQuantumConfig())
        assert cfg.post_quantum.enabled is False
        assert cfg.post_quantum.hybrid_mode is True


class TestAppConfigWithOpenssl:
    def test_openssl_section(self):
        cfg = AppConfig(
            auth=AuthConfig(api_keys=["k"]),
            webhook=WebhookConfig(),
            repo=RepoConfig(url="git@github.com:org/dns-zones.git"),
            openssl=OpensslConfig(key_algorithm="rsa", rsa_key_size=4096),
        )
        assert cfg.openssl is not None
        assert cfg.openssl.key_algorithm == "rsa"
        assert cfg.openssl.rsa_key_size == 4096

    def test_openssl_optional(self):
        cfg = AppConfig(
            auth=AuthConfig(api_keys=["k"]),
            webhook=WebhookConfig(),
            repo=RepoConfig(url="git@github.com:org/dns-zones.git"),
        )
        assert cfg.openssl is None

    def test_load_yaml_with_openssl(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump(
                {
                    "auth": {"api_keys": ["sk-test"]},
                    "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                    "repo": {"url": "git@github.com:org/dns-zones.git"},
                    "openssl": {
                        "key_algorithm": "ecdsa",
                        "ecdsa_curve": "secp521r1",
                        "signature_hash": "sha512",
                    },
                }
            )
        )
        cfg = load_config(str(path))
        assert cfg.openssl is not None
        assert cfg.openssl.key_algorithm == "ecdsa"
        assert cfg.openssl.ecdsa_curve == "secp521r1"
        assert cfg.openssl.signature_hash == "sha512"


class TestMonitorConfigWithPercentage:
    def test_renew_percentage_default_none(self):
        cfg = MonitorConfig()
        assert cfg.renew_percentage is None

    def test_renew_percentage_set(self):
        cfg = MonitorConfig(renew_percentage=15)
        assert cfg.renew_percentage == 15

    def test_renew_percentage_zero(self):
        cfg = MonitorConfig(renew_percentage=0)
        assert cfg.renew_percentage == 0

    def test_renew_percentage_backward_compatible(self):
        cfg = MonitorConfig()
        assert cfg.renew_threshold == 14
        assert cfg.renew_percentage is None

    def test_both_thresholds_can_coexist(self):
        cfg = MonitorConfig(renew_threshold=14, renew_percentage=15)
        assert cfg.renew_threshold == 14
        assert cfg.renew_percentage == 15
