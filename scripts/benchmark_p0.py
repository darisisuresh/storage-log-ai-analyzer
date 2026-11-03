"""Reproducible P0 high-cardinality streaming benchmark; no network or customer data."""
import argparse
import contextlib
import io
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def worker(path):
    from storage_log_analyzer.cli import build_parser
    started = time.perf_counter()
    args = build_parser().parse_args(['analyze', path, '--format', 'json', '--fail-on', 'never'])
    with contextlib.redirect_stdout(io.StringIO()) as output:
        code = args.func(args)
    if code:
        raise RuntimeError(f'Analysis failed: {code}')
    report = json.loads(output.getvalue())
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform != 'darwin':
        rss *= 1024
    print(json.dumps({'events': report['event_count'], 'incidents': sum(f['incident_count'] for f in report['findings']), 'peak_rss_mib': round(rss / 1024**2, 2), 'seconds': round(time.perf_counter() - started, 2)}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker')
    parser.add_argument('--format', choices=['log', 'json'], default='log')
    parser.add_argument('--events', type=int, default=1000000)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    results = []
    with tempfile.TemporaryDirectory(prefix='storage-benchmark-') as directory:
        for count in (args.events // 10, args.events):
            path = Path(directory) / f'{count}.{args.format}'
            with path.open('w') as out:
                if args.format == 'json':
                    out.write('[')
                for number in range(count):
                    if args.format == 'json':
                        row = {'timestamp': '2026-11-02T10:00:00Z', 'host': f'array-{number}', 'vendor': 'pure', 'message': 'disk 7 failed'}
                        out.write((',' if number else '') + json.dumps(row))
                    else:
                        out.write(f'2026-11-02T10:00:00Z host=array-{number} Pure Storage disk 7 failed\n')
                if args.format == 'json':
                    out.write(']')
            env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
            completed = subprocess.run([sys.executable, __file__, '--worker', str(path)], env=env, text=True, capture_output=True, check=True)
            result = json.loads(completed.stdout)
            assert result['events'] == count and result['incidents'] == count
            assert result['peak_rss_mib'] < 128, result
            results.append(result)
            print(json.dumps(result), flush=True)
        assert results[1]['peak_rss_mib'] - results[0]['peak_rss_mib'] < 32, results
    print('PASS: correct event/incident counts; peak RSS <128 MiB; growth <32 MiB for 10x events.')


if __name__ == '__main__':
    main()
