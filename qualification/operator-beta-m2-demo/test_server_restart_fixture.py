"""Focused controls for read-only fixture semantics, not live integration."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import server_restart_fixture as fixture


class ReadOnlyProjection(unittest.TestCase):
    def test_readiness_not_visible_until_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'server-0.json'
            original_dump = json.dump
            def partial(value, stream, **kwargs):
                self.assertFalse(target.exists())
                stream.write('{')
                stream.flush()
                self.assertFalse(target.exists())
                stream.seek(0)
                original_dump(value, stream, **kwargs)
            with mock.patch.object(fixture.json, 'dump', side_effect=partial):
                fixture.retain(target, {'pid': 42})
            self.assertEqual(json.loads(target.read_bytes()), {'pid': 42})
            with self.assertRaises(FileExistsError):
                fixture.retain(target, {'pid': 99})
            self.assertEqual(json.loads(target.read_bytes()), {'pid': 42})

    def test_stop_timeout_records_exact_child_result_before_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'stop.json'
            child = mock.Mock(pid=42)
            child.poll.return_value = None
            child.wait.side_effect = [fixture.subprocess.TimeoutExpired('fixture', 10), -9]
            with self.assertRaises(RuntimeError):
                fixture.stop_child(child, record)
            self.assertEqual(json.loads(record.read_bytes()),
                             {'pid': 42, 'exit': -9, 'stop_bound_exceeded': True})
            child.terminate.assert_called_once()
            child.kill.assert_called_once()

    def test_reopen_does_not_mutate_or_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, calls = root / 'projection.json', root / 'calls.txt'
            fixture.retain(source, fixture.Fixture('success').value)
            original = source.read_bytes()
            for _ in range(2):
                reopened = fixture.ReadOnlyFixture(source, calls)
                self.assertEqual(reopened.query('status'), json.loads(original))
                with self.assertRaises(fixture.demo.Unavailable):
                    reopened.query('start')
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(calls.read_text().splitlines(), ['status', 'start'] * 2)

    def test_missing_or_invalid_source_never_becomes_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'projection.json'
            owner = fixture.ReadOnlyFixture(source, root / 'calls.txt')
            with self.assertRaises(FileNotFoundError):
                owner.query('status')
            fixture.retain(source, {'state': 'success'})
            with self.assertRaises(ValueError):
                owner.query('status')


if __name__ == '__main__':
    unittest.main()
