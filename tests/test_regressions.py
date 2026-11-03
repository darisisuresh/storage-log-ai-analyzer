import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from storage_log_analyzer import __version__
from storage_log_analyzer.cli import build_parser
from storage_log_analyzer.ingest import parse_file
from storage_log_analyzer.models import AnalysisReport, Finding


class InputRegressionTests(unittest.TestCase):
    def parse(self, suffix, content, vendor='auto'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ('events' + suffix)
            path.write_text(content)
            return parse_file(path, vendor)

    def test_explicit_vendor_takes_precedence(self):
        events = self.parse('.log', 'HPE Alletra drive failed', 'pure')
        self.assertEqual(events[0].vendor, 'pure')

    def test_jsonl_non_objects_remain_readable(self):
        events = self.parse('.jsonl', '[1, 2]\n"HPE drive failed"\n42\ntrue\n')
        self.assertEqual(len(events), 4)
        self.assertEqual(events[1].vendor, 'hpe')

    def test_json_invalid_top_level_is_actionable(self):
        for value in (None, True, 123, 'text'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'JSON must'):
                self.parse('.json', json.dumps(value))

    def test_json_events_must_be_array(self):
        for value in (None, {'message': 'error'}, 'text'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'events.*array'):
                self.parse('.json', json.dumps({'events': value}))

    def test_json_object_and_envelope(self):
        row = {'message': 'HPE drive failed'}
        for value in (row, [row], {'events': [row]}):
            with self.subTest(value=value):
                self.assertEqual(self.parse('.json', json.dumps(value))[0].vendor, 'hpe')

    def test_empty_analysis_does_not_claim_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            args = build_parser().parse_args(['analyze', directory])
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(args.func(args), 1)
            self.assertIn('No supported events', err.getvalue())

    def test_file_access_errors_are_reported(self):
        for command in ('analyze', 'summary', 'validate'):
            with self.subTest(command=command):
                args = build_parser().parse_args([command, 'unreadable.log'])
                with patch('storage_log_analyzer.cli.ingest', side_effect=PermissionError('denied')):
                    with contextlib.redirect_stderr(io.StringIO()) as err:
                        self.assertEqual(args.func(args), 1)
                    self.assertIn('denied', err.getvalue())

    def test_version_command(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as exc:
                build_parser().parse_args(['--version'])
        self.assertEqual(exc.exception.code, 0)
        self.assertIn(__version__, out.getvalue())


try:
    import openai
except ImportError:
    openai = None


@unittest.skipIf(openai is None, 'optional AI SDK is not installed')
class AIRegressionTests(unittest.TestCase):
    def report(self):
        return AnalysisReport([], 1, {'pure': 1}, {'high': 1}, [
            Finding('TEST', 'high', 'security', 'Test', ['admin@example.com 10.2.3.4'])
        ])

    def test_redacted_request_uses_current_sdk_and_disables_storage(self):
        from storage_log_analyzer.ai import assess
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-placeholder'}):
            with patch('openai.OpenAI') as factory:
                client = factory.return_value.__enter__.return_value
                client.responses.create.return_value = SimpleNamespace(output_text='Assessment')
                self.assertEqual(assess(self.report()), 'Assessment')
                kwargs = client.responses.create.call_args.kwargs
                self.assertFalse(kwargs['store'])
                self.assertNotIn('admin@example.com', kwargs['input'])
                self.assertNotIn('10.2.3.4', kwargs['input'])
                factory.assert_called_once_with(timeout=60.0, max_retries=2)

    def test_api_errors_do_not_echo_provider_content(self):
        from storage_log_analyzer.ai import assess
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-placeholder'}):
            with patch('openai.OpenAI') as factory:
                client = factory.return_value.__enter__.return_value
                client.responses.create.side_effect = openai.APIError(
                    'sensitive-provider-message', request=None, body=None
                )
                with self.assertRaises(RuntimeError) as exc:
                    assess(self.report())
                self.assertNotIn('sensitive-provider-message', str(exc.exception))
                self.assertIn('APIError', str(exc.exception))

    def test_empty_ai_response_is_actionable(self):
        from storage_log_analyzer.ai import assess
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-placeholder'}):
            with patch('openai.OpenAI') as factory:
                factory.return_value.__enter__.return_value.responses.create.return_value = SimpleNamespace(output_text='')
                with self.assertRaisesRegex(RuntimeError, 'returned no text'):
                    assess(self.report())


@unittest.skipIf(openai is None, "optional AI SDK is not installed")
class SDKTransportTests(unittest.TestCase):
    def test_responses_round_trip_without_network(self):
        import httpx2
        from storage_log_analyzer.ai import assess

        requests = []

        def respond(request):
            requests.append(json.loads(request.content))
            return httpx2.Response(200, json={
                "id": "resp_test", "created_at": 0, "object": "response",
                "model": "test-model", "status": "completed",
                "output": [{"id": "msg_test", "type": "message", "role": "assistant",
                            "status": "completed", "content": [{"type": "output_text",
                            "text": "Mocked SDK assessment", "annotations": []}]}]
            })

        client = openai.OpenAI(api_key="test-placeholder", http_client=httpx2.Client(
            transport=httpx2.MockTransport(respond)
        ))
        report = AnalysisReport([], 0, {}, {}, [])
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-placeholder"}):
            with patch("openai.OpenAI", return_value=client):
                self.assertEqual(assess(report, "test-model"), "Mocked SDK assessment")
        self.assertFalse(requests[0]["store"])
        self.assertEqual(requests[0]["model"], "test-model")
