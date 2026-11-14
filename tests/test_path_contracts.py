"""Regression checks for candidate interchange and source-location contracts."""

import json
import re
import tempfile
import unittest
from pathlib import Path

from path_explore.models import VulnerabilityPath
from path_explore.utils import read_source_code_by_range
from path_verify.models import (
    DataflowInfo,
    FilterLogic,
    NodeDataflowRecord,
    PathNode,
    VerificationResult,
)
from path_verify.utils import load_potential_paths


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "sast_paths"


class CandidateInterchangeTests(unittest.TestCase):
    def test_exported_candidate_can_be_loaded_and_read_by_verifier(self):
        original = json.loads((EXAMPLE / "potential_paths.json").read_text())
        path = load_potential_paths(str(EXAMPLE / "potential_paths.json"))[0]
        exported = VulnerabilityPath(
            vulnerability_type=path.vulnerability_type,
            sink_expression=path.sink_expression,
            interface_name=path.interface_name,
            path=[(n.file_path, n.function_name, n.start_line, n.end_line) for n in path.path],
        ).to_dict()
        self.assertEqual([exported], original)
        self.assertEqual(path.get_call_chain_display(), "read -> readFile -> sink")
        for node in path.path:
            source = node.get_source_code(str(EXAMPLE))
            self.assertIn(node.function_name + "(", source)
            self.assertTrue(source.rstrip().endswith("}"))
        self.assertIn(path.sink_expression, path.path[-1].get_source_code(str(EXAMPLE)))

    def test_both_readme_examples_match_the_bundled_candidate(self):
        expected = json.loads((EXAMPLE / "potential_paths.json").read_text())
        for name in ("README.md", "README_CN.md"):
            with self.subTest(readme=name):
                examples = re.findall(r"```json\n(.*?)\n```", (ROOT / name).read_text(), re.S)
                self.assertEqual(len(examples), 1)
                self.assertEqual(json.loads(examples[0]), expected)

    def test_result_export_preserves_locations_and_supporting_evidence(self):
        path = load_potential_paths(str(EXAMPLE / "potential_paths.json"))[0]
        result = VerificationResult(
            vulnerability_type=path.vulnerability_type,
            sink_expression=path.sink_expression,
            path=path.path,
            interface_name=path.interface_name,
            dataflow_records=[NodeDataflowRecord(
                0, "read", DataflowInfo(parameters=["fileName"], non_local_sources=["test fixture read"])
            )],
            filter_logics=[FilterLogic("fileName", "Fixture evidence", "ExampleController.java", (7, 9))],
        ).to_dict()
        serialized = json.loads(json.dumps(result))
        self.assertEqual(serialized["Path"], [n.to_dict() for n in path.path])
        self.assertEqual(serialized["DataflowAnalysis"][0]["NonLocalSources"], ["test fixture read"])
        self.assertEqual(serialized["FilterLogics"][0]["Lines"], "7-9")
        self.assertEqual(serialized["InterfaceName"], "/example/read")


class SourceLocationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = '// header\nvoid read() {\n    String value = "路径";\n}\n// footer\n'
        (self.root / "Example.java").write_text(self.source, encoding="utf-8")

    def test_explorer_and_verifier_read_the_same_inclusive_unicode_range(self):
        expected = 'void read() {\n    String value = "路径";\n}'
        node = PathNode("Example.java", "read", 2, 4)
        self.assertEqual(node.get_source_code(str(self.root)), expected)
        self.assertEqual(read_source_code_by_range(str(self.root), "Example.java", 2, 4), expected)

    def test_ranges_beyond_eof_stop_at_the_file_boundary(self):
        node = PathNode("Example.java", "read", 2, 999)
        self.assertEqual(node.get_source_code(str(self.root)), "\n".join(self.source.splitlines()[1:]))

    def test_invalid_verifier_ranges_return_no_source(self):
        for start, end in ((0, 4), (4, 2)):
            with self.subTest(start=start, end=end):
                self.assertEqual(PathNode("Example.java", "read", start, end).get_source_code(str(self.root)), "")

    def test_empty_source_file_is_handled_by_both_readers(self):
        (self.root / "Empty.java").write_text("")
        self.assertEqual(PathNode("Empty.java", "read", 1, 4).get_source_code(str(self.root)), "")
        self.assertEqual(read_source_code_by_range(str(self.root), "Empty.java", 1, 4), "")
