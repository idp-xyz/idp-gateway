"""The one agentgateway build this repository is developed and tested against.

deploy/agentgateway/agentgateway.lock.json names it: the version, the git revision the binary
reports about itself, the upstream container image by digest, and the SHA-256 of the binary
inside that image. What is deployed is that image; what the black-box runner and the
Gatekeeper integration runner start is the binary taken out of it. Both take it from
resolve() and start no other.

The release page also offers a stand-alone binary. It is another build of the same revision
(musl instead of glibc) and is not the one pinned here.

    python tests/acceptance/blackbox/pin.py           which binary would be used, and is it the pinned one
    python tests/acceptance/blackbox/pin.py --fetch   take the binary out of the pinned image (needs docker)
"""
from __future__ import annotations
import hashlib, json, os, platform, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / 'deploy/agentgateway/agentgateway.lock.json'
PLATFORMS = {'x86_64': 'linux/amd64', 'amd64': 'linux/amd64', 'aarch64': 'linux/arm64', 'arm64': 'linux/arm64'}


class PinError(Exception):
    """There is no binary to run, or the one found is not the pinned build."""


def lock() -> dict:
    return json.loads(LOCK.read_text(encoding='utf-8'))


def home_copy(pinned: dict) -> Path:
    """Where a per-user copy of the pinned build is looked for, before PATH."""
    return Path.home() / '.local/opt/agentgateway' / pinned['version'] / 'agentgateway'


def image_reference(pinned: dict, platform_name: str | None = None) -> str:
    """repository@digest: of the manifest for one platform, or of the multi-platform index."""
    image = pinned['image']
    return f"{image['repository']}@{image['manifests'][platform_name] if platform_name else image['index']}"


def resolve(explicit: str | None = None) -> tuple[str, dict]:
    """-> (path of the binary, what it reports with --version). Raises PinError.

    explicit is a path or a command name given by the user. Without it the per-user copy is
    taken if there is one, otherwise `agentgateway` on PATH. Whichever is found first is the
    only candidate: when it is not the pinned build the answer is an error, not the next place.
    """
    pinned = lock()
    where = LOCK.relative_to(ROOT).as_posix()
    home = home_copy(pinned)
    how = (f"Run `python {Path(__file__).resolve().relative_to(ROOT).as_posix()} --fetch` to take {pinned['image']['binary']} "
           f"out of {image_reference(pinned)} and put it at {home}.")
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
        problems.append(f"its SHA-256 is {digest}, which is not that of the binary in the pinned image "
                        f"(build target reported: {reported.get('build_target')})")
    if problems:
        raise PinError(f"{binary} is not the agentgateway build pinned in {where}: {'; '.join(problems)}. {how}")
    return str(binary), reported


def fetch() -> Path:
    """Take the binary out of the pinned image for this machine's platform and put it at home_copy().

    The image is pulled by the digest of its manifest, so what arrives is what the lock names or
    nothing; the binary is then checked against the lock before it replaces anything."""
    pinned = lock()
    platform_name = PLATFORMS.get(platform.machine().lower())
    if platform_name not in pinned['image']['manifests']:
        raise PinError(f'the lock names no image for this platform ({platform.machine()})')
    reference = image_reference(pinned, platform_name)

    def docker(*argv: str) -> str:
        try:
            done = subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.SubprocessError) as e:
            raise PinError(f"docker {argv[0]} could not be run: {type(e).__name__}: {e}")
        if done.returncode != 0:
            raise PinError(f"docker {argv[0]} failed: {done.stderr.strip()[-300:]}")
        return done.stdout.strip()

    docker('pull', '-q', reference)
    container = docker('create', reference)
    target = home_copy(pinned)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, scratch = tempfile.mkstemp(dir=target.parent, prefix='.fetch-')
    os.close(handle)
    try:
        docker('cp', f"{container}:{pinned['image']['binary']}", scratch)
        digest = hashlib.sha256(Path(scratch).read_bytes()).hexdigest()
        if digest not in pinned['sha256'].values():
            raise PinError(f"{pinned['image']['binary']} in {reference} has SHA-256 {digest}, which the lock does not name")
        os.chmod(scratch, 0o755)
        os.replace(scratch, target)
    finally:
        Path(scratch).unlink(missing_ok=True)
        docker('rm', container)
    return target


def main() -> int:
    try:
        if sys.argv[1:] == ['--fetch']:
            print(f'fetched {fetch()}')
        elif sys.argv[1:]:
            print(__doc__.strip().split('\n\n')[-1]); return 2
        binary, reported = resolve()
    except PinError as e:
        print(e); return 1
    print(f"{binary}: agentgateway {reported['version']} at {reported['git_revision'][:12]}, {reported.get('build_target')}; "
          f"the build pinned in {LOCK.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
