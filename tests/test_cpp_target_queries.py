import dataclasses
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from project_source import CppContextCompilerProvider, Repository, SourceIndex


class FullScanSourceIndex(SourceIndex):
    """Independent unfiltered reference: inspect every file before traversal."""
    def _cpp_candidate_paths(self, paths, query, **kwargs):
        return paths

    def _cpp_coverage_partial(self, paths, query, **kwargs):
        return False  # The full extraction loop below checks every file instead.

    def _cpp_validate_query(self, query):
        return

    def _cpp_trace_results(self, paths, query, starts, predicates, direction, max_hops, python_edges):
        results = []
        partial = False
        for path in paths:
            try:
                result = self.structure(path)
            except (OSError, ValueError):
                partial = True
                continue
            results.append((path, result))
            partial |= result.coverage != 'complete'
        return results, partial


class CppTargetQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'repo'
        self.root.mkdir()
        sources = {
            'src/a.cpp': 'int alpha() { return 1; }\n',
            'src/b.cpp': 'int beta() { return 2; }\n',
            'src/c.cpp': 'int gamma() { return 3; }\n',
            'src/d.cpp': 'int delta() { return 4; }\n',
            'src/other.cpp': 'int unrelated() { return 5; }\n',
            'include/a.hh': 'int alpha();\n',
            'tests/alpha_test.cpp': 'int alpha_test() { return 0; }\n',
            'unindexed.cpp': 'int outside_export() { return 0; }\n',
            'consumer.py': 'def alpha():\n    return 1\n\ndef caller():\n    return alpha()\n',
        }
        for name, text in sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        records = []
        for name in sources:
            if not name.endswith(('.cpp', '.hh')) or name == 'unindexed.cpp':
                continue
            records.append({'record': 'file', 'path': name,
                'hash': hashlib.sha256((self.root / name).read_bytes()).hexdigest(), 'parse_status': 'ok'})
        for name, identifier, symbol, definition in [
            ('src/a.cpp', 'f-a', 'alpha', True), ('src/b.cpp', 'f-b', 'beta', True),
            ('src/c.cpp', 'f-c', 'gamma', True), ('src/d.cpp', 'f-d', 'delta', True),
            ('src/other.cpp', 'f-u', 'unrelated', True), ('include/a.hh', 'f-a', 'alpha', False),
            ('tests/alpha_test.cpp', 'f-t', 'alpha_test', True),
        ]:
            records.append({'record': 'symbol', 'file': name, 'id': identifier,
                'name': symbol, 'qualified_name': symbol, 'line': 1, 'end_line': 1,
                'definition': definition})
        for path, source, target, kind, config in [
            ('src/a.cpp', 'f-a', 'f-b', 'call', 'config-1'),
            ('src/a.cpp', 'f-a', 'f-b', 'call', 'config-2'),
            ('src/a.cpp', 'f-a', 'include/a.hh', 'include', 'config-1'),
            ('src/b.cpp', 'f-b', 'f-c', 'type_use', 'config-1'),
            ('src/c.cpp', 'f-c', 'f-a', 'member_access', 'config-1'),
            ('src/other.cpp', 'f-u', 'f-d', 'reference', 'config-1'),
            ('tests/alpha_test.cpp', 'f-t', 'f-a', 'test_relationship', 'config-1'),
        ]:
            records.append({'record': 'edge', 'file': path, 'from': source, 'to': target,
                'type': kind, 'start': 0, 'end': 3, 'configuration_hash': config})
        self.export = self.base / 'export.json'
        self.export.write_text(json.dumps({'format': 'CTXPP-EXPORT/1', 'root': str(self.root),
            'index_integrity': True, 'index_meta': {'semantic': True},
            'freshness': {'status': 'fresh'}, 'records': records}))

    def indexes(self, deny=()):
        new = SourceIndex(Repository(self.root, 'fixture', self.base / 'new', deny_patterns=deny),
            [CppContextCompilerProvider(self.export)])
        old = FullScanSourceIndex(Repository(self.root, 'fixture', self.base / 'old', deny_patterns=deny),
            [CppContextCompilerProvider(self.export)])
        return new, old

    def test_exact_resolution_preserves_python_cpp_ambiguity_without_unrelated_extraction(self):
        new, old = self.indexes()
        for name in ('alpha', 'beta', 'outside_export', 'missing', 'f-b'):
            self.assertEqual(new.resolve(name), old.resolve(name), name)
        with patch.object(new, 'structure', wraps=new.structure) as structure:
            self.assertEqual(new.resolve('beta')['resolution'], 'resolved')
        self.assertEqual([call.args[0] for call in structure.call_args_list], ['src/b.cpp'])
        self.assertEqual(new.resolve('alpha')['resolution'], 'ambiguous')

    def test_context_preserves_relationships_budget_and_partial_coverage(self):
        new, old = self.indexes()
        target = {'kind': 'symbol', 'target': 'beta', 'symbol': 'beta', 'path': 'src/b.cpp'}
        for include in (('implementation',), ('implementation', 'callers', 'references', 'tests', 'guidance')):
            for budget in (70, 4000):
                actual = dataclasses.asdict(new.context([target], include=include, budget_bytes=budget))
                expected = dataclasses.asdict(old.context([target], include=include, budget_bytes=budget))
                self.assertEqual(actual, expected, (include, budget))
        packet = new.context([target], include=('implementation', 'callers'), budget_bytes=4000)
        self.assertTrue(any('partial coverage' in str(item) for item in packet.omissions))
        self.assertEqual(len(packet.sections['callers']), 2, 'configuration duplicates must be preserved')

    def test_trace_matches_prior_all_directions_cycles_hops_predicates_and_limits(self):
        for deny in ((), ('src/b.cpp',)):
            new, old = self.indexes(deny)
            for target in ('alpha', 'beta', 'f-a', 'src/a.cpp', 'include/a.hh'):
                for direction in ('out', 'in', 'both'):
                    for hops in (0, 1, 2, 3):
                        for predicates in ((), ('call',), ('test_relationship',)):
                            for limit in (3, 100):
                                args = dict(direction=direction, max_hops=hops, predicates=predicates, limit=limit)
                                self.assertEqual(new.trace([target], **args), old.trace([target], **args),
                                    (deny, target, args))

    def test_unrelated_stale_or_unindexed_source_keeps_global_partial_coverage(self):
        new, old = self.indexes()
        (self.root / 'src/other.cpp').write_text('int now_stale() { return 9; }\n')
        self.assertEqual(new.trace(['beta']), old.trace(['beta']))
        self.assertEqual(new.trace(['beta'])['coverage'], 'partial')
        target = {'kind': 'symbol', 'target': 'beta', 'symbol': 'beta', 'path': 'src/b.cpp'}
        self.assertEqual(dataclasses.asdict(new.context([target])), dataclasses.asdict(old.context([target])))

    def test_initially_unavailable_export_cannot_join_a_new_generation_mid_query(self):
        for invalid in (None, '{'):
            new, _ = self.indexes()
            valid = self.export.read_text()
            if invalid is None:
                self.export.unlink()
            else:
                self.export.write_text(invalid)
            capture = new._cpp_query
            def recover():
                query = capture()
                self.export.write_text(valid)
                return query
            with patch.object(new, '_cpp_query', side_effect=recover):
                with self.assertRaisesRegex(ValueError, 'changed during source query'):
                    new.resolve('beta')

    def test_trace_accepts_single_use_selector_iterables(self):
        new, _ = self.indexes()
        expected = new.trace(['alpha'], predicates=('call',), max_hops=2)
        self.assertEqual(new.trace(iter(['alpha']), predicates=iter(['call']), max_hops=2), expected)

    def test_export_replacement_during_resolve_fails_closed(self):
        new, _ = self.indexes()
        original = new.structure
        changed = False
        def replace(path, *args, **kwargs):
            nonlocal changed
            result = original(path, *args, **kwargs)
            if not changed:
                envelope = json.loads(self.export.read_text())
                envelope['index_meta']['incomplete'] = True
                self.export.write_text(json.dumps(envelope))
                changed = True
            return result
        with patch.object(new, 'structure', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'changed during source query'):
                new.resolve('beta')


if __name__ == '__main__':
    unittest.main()
