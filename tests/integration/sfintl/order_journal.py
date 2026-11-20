"""One file per --sandbox run, so a killed run still names the orders to cancel by hand.

orders-<UTC timestamp>-<pid>.jsonl under DIRECTORY, mode 0600. Each line is
{"at", "event", "customerOrderNo", "sfWaybillNo", "run"} and nothing else.
Nothing is written until begin() (call it only for --sandbox). The file is removed
at the end only when every order in it was cancelled; an earlier file is left in place.
"""
from __future__ import annotations
import datetime, json, os
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent / '.run'
PATH: Path | None = None
_state: dict[str, str] = {}


def begin() -> list[Path]:
    """Name this run's file. Returns orders-*.jsonl already in DIRECTORY; they are not deleted."""
    global PATH
    DIRECTORY.mkdir(exist_ok=True)
    earlier = sorted(path for path in DIRECTORY.glob('orders-*.jsonl') if path.is_file())
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    PATH = DIRECTORY / f'orders-{stamp}-{os.getpid()}.jsonl'
    extra = 0
    while PATH.exists():
        extra += 1
        PATH = DIRECTORY / f'orders-{stamp}-{os.getpid()}-{extra}.jsonl'
    _state.clear()
    return earlier


def warning(paths: list[Path]) -> str:
    if not paths:
        return ''
    return 'warning: sandbox orders from an earlier run are still on disk: ' + ', '.join(str(path) for path in paths)


def created(order_no: str, waybill: str) -> None:
    if PATH is None or not isinstance(waybill, str) or not waybill or waybill in _state:
        return
    _state[waybill] = 'created'
    _write('created', order_no, waybill)


def cancelled(order_no: str, waybill: str) -> None:
    if PATH is None or _state.get(waybill) != 'created':
        return
    _state[waybill] = 'cancelled'
    _write('cancelled', order_no, waybill)


def finish() -> None:
    """Unlink this run's file only when every order in it was cancelled. Never raises."""
    global PATH
    path, PATH = PATH, None
    still_open = any(status != 'cancelled' for status in _state.values())
    _state.clear()
    try:
        if path is not None and path.is_file() and not still_open and not _open_waybills(path):
            path.unlink()
    except Exception:
        pass


def _open_waybills(path: Path) -> set[str]:
    open_bills: set[str] = set()
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        bill = row.get('sfWaybillNo')
        if isinstance(bill, str) and bill and row.get('event') == 'cancelled':
            open_bills.discard(bill)
        elif isinstance(bill, str) and bill and row.get('event') == 'created':
            open_bills.add(bill)
    return open_bills


def _write(event: str, order_no: str, waybill: str) -> None:
    line = (json.dumps({'at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                        'event': event, 'customerOrderNo': order_no if isinstance(order_no, str) else '',
                        'sfWaybillNo': waybill, 'run': os.getpid()}, ensure_ascii=False) + '\n').encode()
    try:
        fd = os.open(PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            first = os.fstat(fd).st_size == 0
            try:
                os.chmod(PATH, 0o600)
            except OSError:
                pass
            os.write(fd, line)
            try:
                os.fsync(fd)
            except OSError:
                pass
            if first:
                try:
                    dir_fd = os.open(DIRECTORY, os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
        finally:
            os.close(fd)
    except OSError:
        pass
