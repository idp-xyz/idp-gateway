"""Sandbox order journal: a killed --sandbox run still names the orders it created.

OFFLINE. Loads tests/integration/sfintl/order_journal.py by path and does not import run.py.
run.py imports the Gatekeeper rig, which exits when tests/integration/gatekeeper/.run/stack.env is absent.
"""
import importlib.util, json, os, stat, tempfile, unittest
from pathlib import Path

R = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('order_journal', R / 'tests/integration/sfintl/order_journal.py')
journal = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(journal)
FIELDS = {'at', 'event', 'customerOrderNo', 'sfWaybillNo', 'run'}


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def _open(path: Path) -> set[str]:
    open_bills: set[str] = set()
    for row in _rows(path):
        bill = row['sfWaybillNo']
        if row['event'] == 'cancelled':
            open_bills.discard(bill)
        elif row['event'] == 'created':
            open_bills.add(bill)
    return open_bills


class OrderJournal(unittest.TestCase):
    def test_open_orders_stay_on_disk_and_the_next_run_is_warned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            journal.PATH = None
            journal.DIRECTORY = root
            journal.created('IDPGW-0', 'SF000')
            self.assertEqual(list(root.glob('orders-*.jsonl')), [])
            self.assertEqual(journal.warning(journal.begin()), '')
            journal.created('IDPGW-1', 'SF001')
            journal.created('IDPGW-1', 'SF001')
            journal.created('IDPGW-2', 'SF002')
            path = next(root.glob('orders-*.jsonl'))
            self.assertTrue(path.name.startswith('orders-') and path.name.endswith(f'-{os.getpid()}.jsonl'))
            journal.cancelled('IDPGW-1', 'SF001')
            found = _rows(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertTrue(all(set(row) == FIELDS for row in found))
            self.assertNotRegex(path.read_text(encoding='utf-8'), r'secret|authorization|app_key|token')
            self.assertEqual([(row['event'], row['customerOrderNo'], row['sfWaybillNo']) for row in found],
                             [('created', 'IDPGW-1', 'SF001'), ('created', 'IDPGW-2', 'SF002'), ('cancelled', 'IDPGW-1', 'SF001')])
            self.assertEqual(_open(path), {'SF002'})
            self.assertEqual(found[0]['run'], os.getpid())
            self.assertRegex(found[0]['at'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$')
            journal.cancelled('IDPGW-2', 'SF002')
            journal.finish()
            self.assertFalse(path.exists())
            journal.begin()
            journal.created('IDPGW-9', 'SF009')
            leftover = next(root.glob('orders-*.jsonl'))
            journal.finish()
            self.assertTrue(leftover.is_file())
            noted = journal.begin()
            self.assertEqual(noted, [leftover])
            self.assertIn(str(leftover), journal.warning(noted))
            self.assertTrue(leftover.is_file())
