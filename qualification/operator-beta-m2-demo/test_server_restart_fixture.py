"""Focused controls for read-only fixture semantics, not live integration."""
import json
from pathlib import Path
import tempfile
import unittest

import server_restart_fixture as fixture


class ReadOnlyProjection(unittest.TestCase):
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
