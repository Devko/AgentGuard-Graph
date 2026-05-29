import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import sample_paths
from agentguard_graph.adapters.events import parse_events
from agentguard_graph.errors import EvidenceLoadError


class EventAdapterTests(unittest.TestCase):
    def test_runtime_event_jsonl_parsing(self):
        parsed = parse_events(sample_paths("support-agent")["events"])
        self.assertEqual(parsed["events"][0]["event_type"], "agent.tool_call")
        self.assertEqual(parsed["events"][0]["input_trust"], "untrusted")

    def test_malformed_jsonl_has_useful_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"event_type":"agent.tool_call"}\n{bad json}\n', encoding="utf-8")
            with self.assertRaises(EvidenceLoadError) as ctx:
                parse_events(path)
            self.assertIn("invalid JSONL", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
