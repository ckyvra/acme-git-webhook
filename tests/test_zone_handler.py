from pathlib import Path

import pytest

from app.zone_handler import _resolve_zone_path, add_txt_record, remove_txt_record


class TestResolveZonePath:
    def test_direct_match(self, tmp_path: Path):
        zone = tmp_path / "zones" / "example.com.zone"
        zone.parent.mkdir(parents=True, exist_ok=True)
        zone.write_text("")

        result = _resolve_zone_path(tmp_path, "_acme-challenge.example.com", "zones", ".zone")
        assert result == zone

    def test_wildcard_domain(self, tmp_path: Path):
        zone = tmp_path / "zones" / "example.com.zone"
        zone.parent.mkdir(parents=True, exist_ok=True)
        zone.write_text("")

        result = _resolve_zone_path(tmp_path, "_acme-challenge.*.example.com", "zones", ".zone")
        assert result == zone

    def test_subdomain_falls_back_to_parent(self, tmp_path: Path):
        parent_zone = tmp_path / "zones" / "example.com.zone"
        parent_zone.parent.mkdir(parents=True, exist_ok=True)
        parent_zone.write_text("")

        result = _resolve_zone_path(tmp_path, "_acme-challenge.sub.example.com", "zones", ".zone")
        assert result == parent_zone

    def test_no_zone_found(self, tmp_path: Path):
        result = _resolve_zone_path(tmp_path, "_acme-challenge.unknown.org", "zones", ".zone")
        assert result is None

    def test_exact_subdomain_match_wins(self, tmp_path: Path):
        zones = tmp_path / "zones"
        zones.mkdir(parents=True, exist_ok=True)
        parent = zones / "example.com.zone"
        child = zones / "sub.example.com.zone"
        parent.write_text("")
        child.write_text("")

        result = _resolve_zone_path(tmp_path, "_acme-challenge.sub.example.com", "zones", ".zone")
        assert result == child

    def test_strips_prefix_only_once(self, tmp_path: Path):
        zone = tmp_path / "zones" / "example.com.zone"
        zone.parent.mkdir(parents=True, exist_ok=True)
        zone.write_text("")

        result = _resolve_zone_path(
            tmp_path, "_acme-challenge._acme-challenge.example.com", "zones", ".zone"
        )
        assert result is not None


class TestAddTxtRecord:
    def test_add_new_record(self, tmp_path: Path, sample_zone: Path):
        add_txt_record(tmp_path, "_acme-challenge.example.com", "abc123", "zones", ".zone")
        content = sample_zone.read_text()
        assert '_acme-challenge' in content
        assert 'abc123' in content

    def test_replace_existing_record(self, tmp_path: Path, sample_zone: Path):
        add_txt_record(tmp_path, "_acme-challenge.example.com", "first", "zones", ".zone")
        add_txt_record(tmp_path, "_acme-challenge.example.com", "second", "zones", ".zone")
        content = sample_zone.read_text()
        assert 'second' in content
        assert 'first' not in content

    def test_raises_on_missing_zone(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            add_txt_record(tmp_path, "_acme-challenge.nonexistent.com", "val", "zones", ".zone")

    def test_returns_zone_file_path(self, tmp_path: Path, sample_zone: Path):
        result = add_txt_record(
            tmp_path, "_acme-challenge.example.com", "val", "zones", ".zone"
        )
        assert result == str(sample_zone)


class TestRemoveTxtRecord:
    def test_remove_existing_record(self, tmp_path: Path, sample_zone: Path):
        add_txt_record(tmp_path, "_acme-challenge.example.com", "toremove", "zones", ".zone")
        assert 'toremove' in sample_zone.read_text()

        remove_txt_record(tmp_path, "_acme-challenge.example.com", "zones", ".zone")
        content = sample_zone.read_text()
        assert 'toremove' not in content

    def test_remove_nonexistent_record_is_idempotent(self, tmp_path: Path, sample_zone: Path):
        result = remove_txt_record(
            tmp_path, "_acme-challenge.example.com", "zones", ".zone"
        )
        assert result is None

    def test_remove_for_missing_zone_returns_none(self, tmp_path: Path):
        result = remove_txt_record(
            tmp_path, "_acme-challenge.unknown.com", "zones", ".zone"
        )
        assert result is None

    def test_returns_zone_file_path_on_success(self, tmp_path: Path, sample_zone: Path):
        add_txt_record(tmp_path, "_acme-challenge.example.com", "val", "zones", ".zone")
        result = remove_txt_record(
            tmp_path, "_acme-challenge.example.com", "zones", ".zone"
        )
        assert result == str(sample_zone)
