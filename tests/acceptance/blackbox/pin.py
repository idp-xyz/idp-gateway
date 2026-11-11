"""The one agentgateway release this repository is developed and tested against.

deploy/agentgateway/agentgateway.lock.json names it: the version, the git revision the binary
reports about itself, and the SHA-256 of each release asset in use. The black-box runner and
the Gatekeeper integration runner both take their binary from resolve() and start no other.
"""
from __future__ import annotations
import hashlib, json, shutil, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / 'deploy/agentgateway/agentgateway.lock.json'


class PinError(Exception):
    """There is no binary to run, or the one found is not the pinned release."""


def lock() -> dict:
    return json.loads(LOCK.read_text(encoding='utf-8'))


def home_copy(pinned: dict) -> Path:
    """Where a per-user copy of the pinned release is looked for, before PATH."""
    return Path.home() / '.local/opt/agentgateway' / pinned['version'] / 'agentgateway'


def resolve(explicit: str | None = None) -> tuple[str, dict]:
    """-> (path of the binary, what it reports with --version). Raises PinError.

    explicit is a path or a command name given by the user. Without it the per-user copy is
    taken if there is one, otherwise `agentgateway` on PATH. Whichever is found first is the
    only candidate: when it is not the pinned release the answer is an error, not the next place.
    """
    pinned = lock()
    where = LOCK.relative_to(ROOT).as_posix()
    home = home_copy(pinned)
    how = (f"Take {' or '.join(pinned['sha256'])} from {pinned['release']}, make it executable and put it at {home} "
           f"or, as `agentgateway`, on PATH.")
    if explicit:
        found = shutil.which(explicit)
        if not found:
            raise PinError(f'agentgateway binary not found: {explicit}')
    else:
        found = str(home) if home.exists() else shutil.which('agentgateway')
        if not found:
            raise PinError(f"agentgateway {pinned['version']} not found: there is no {home} and no agentgateway on PATH. {how}")
    binary = Path(found).resolve()
    try:
        said = subprocess.run([str(binary), '--version'], capture_output=True, text=True, timeout=20).stdout
        reported = json.loads(said)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        raise PinError(f'{binary} could not be read or did not report a version: {type(e).__name__}: {e}')
    if not isinstance(reported, dict):
        raise PinError(f'{binary} did not report a version')
    problems = []
    if (reported.get('version'), reported.get('git_revision')) != (pinned['version'], pinned['git_revision']):
        problems.append(f"it reports version {reported.get('version')} at revision {reported.get('git_revision')}, "
                        f"not {pinned['version']} at {pinned['git_revision']}")
    if digest not in pinned['sha256'].values():
        problems.append(f'its SHA-256 is {digest}, which is not that of a release asset named in the lock')
    if problems:
        raise PinError(f"{binary} is not the agentgateway release pinned in {where}: {'; '.join(problems)}. {how}")
    return str(binary), reported
