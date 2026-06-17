from pathlib import Path

from git import Repo

from app.git_handler import clone_or_pull, commit_and_push


class TestCloneOrPull:
    def test_initial_clone(self, tmp_path: Path, bare_git_repo: Path):
        work_dir = tmp_path / "work"
        repo = clone_or_pull(work_dir, str(bare_git_repo), "main")

        assert repo is not None
        assert (work_dir / "zone-repo").exists()
        assert (work_dir / "zone-repo" / "zones" / "example.com.zone").exists()

    def test_pull_on_existing_clone(self, tmp_path: Path, bare_git_repo: Path):
        work_dir = tmp_path / "work"
        repo = clone_or_pull(work_dir, str(bare_git_repo), "main")
        assert not repo.is_dirty()

        repo = clone_or_pull(work_dir, str(bare_git_repo), "main")
        assert not repo.is_dirty()


class TestCommitAndPush:
    def test_commit_and_push(self, tmp_path: Path, bare_git_repo: Path):
        work_dir = tmp_path / "work"
        repo = clone_or_pull(work_dir, str(bare_git_repo), "main")

        zone_file = work_dir / "zone-repo" / "zones" / "example.com.zone"
        zone_file.write_text(zone_file.read_text() + "\nwww IN A 192.0.2.2\n")

        commit_and_push(work_dir, "Test: add A record")

        bare = Repo(str(bare_git_repo))
        latest = bare.head.commit
        assert "Test" in latest.message

    def test_noop_on_clean_tree(self, tmp_path: Path, bare_git_repo: Path):
        work_dir = tmp_path / "work"
        clone_or_pull(work_dir, str(bare_git_repo), "main")

        commit_and_push(work_dir, "Should not appear")

        bare = Repo(str(bare_git_repo))
        assert "Initial zone" in bare.head.commit.message
