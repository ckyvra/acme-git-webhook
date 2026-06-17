from pathlib import Path

from git import Repo


def clone_or_pull(repo_dir: Path, repo_url: str, branch: str = "main") -> Repo:
    """Clone the zone repository or update an existing clone.

    If the local clone already exists under ``repo_dir / "zone-repo"``,
    a ``git pull --rebase`` is performed to fetch the latest changes
    before any zone modification. Using rebase instead of merge keeps
    the history linear and avoids merge commits when the remote has
    advanced (e.g. after a CI/CD-deployed change). If no local clone
    exists yet, a fresh shallow-like clone is created at the requested
    branch.

    Args:
        repo_dir: Parent directory under which the "zone-repo" folder
            is expected or will be created.
        repo_url: Remote URL (SSH or HTTPS) of the zone Git repository.
        branch: Remote branch to track (default: main).

    Returns:
        A git.Repo instance representing the local clone.
    """
    # Ensure the parent directory exists, then define the clone path.
    repo_dir.mkdir(parents=True, exist_ok=True)
    repo_path = repo_dir / "zone-repo"

    if repo_path.exists():
        # Existing clone — fast-forward to the latest remote state.
        # Rebase keeps the history clean: our ACME commit will sit on
        # top of whatever was pushed by CI/CD in the meantime.
        repo = Repo(repo_path)
        origin = repo.remotes.origin
        origin.pull(rebase=True)
    else:
        # First time — full clone of the requested branch.
        repo = Repo.clone_from(repo_url, repo_path, branch=branch)

    return repo


def commit_and_push(repo_dir: Path, message: str) -> None:
    """Stage all changes, commit and push to the remote.

    Opens the existing clone under ``repo_dir / "zone-repo"``, stages
    every modified and untracked file (``git add -A``), creates a
    commit with the supplied message and pushes it to ``origin``. The
    function is a no-op if the working tree is clean — no empty commits
    are created.

    Args:
        repo_dir: Parent directory containing the "zone-repo" clone.
        message: Commit message describing the change
            (e.g. "ACME: add challenge for example.com").
    """
    repo_path = repo_dir / "zone-repo"
    repo = Repo(repo_path)

    # Only commit and push if something actually changed.
    # Avoids noisy empty commits when cleanup is called on a domain
    # that had no TXT record.
    if repo.is_dirty(untracked_files=True):
        repo.index.add("*")
        repo.index.commit(message)
        origin = repo.remotes.origin
        origin.push()
