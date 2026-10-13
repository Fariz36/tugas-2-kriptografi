"""Save CLI end-to-end smoke evidence for the current cipher revision."""
import json
import subprocess
import sys
from pathlib import Path


def main():
    root = Path('data/cli')
    root.mkdir(parents=True, exist_ok=True)
    log = []
    key = '000102030405060708090a0b0c0d0e0f'
    for mode in ('ECB', 'CBC', 'CFB', 'OFB', 'CTR'):
        encrypted, recovered, stats = (root / (mode + suffix) for suffix in ('.jav', '.txt', '.json'))
        commands = [
            ['encrypt', '--input', 'data/inputs/text_utf8.txt', '--output', str(encrypted), '--key-hex', key, '--mode', mode],
            ['decrypt', '--input', str(encrypted), '--output', str(recovered), '--key-hex', key],
            ['analyze', '--input', str(encrypted), '--plaintext', str(recovered), '--output', str(stats), '--key-hex', key],
        ]
        for args in commands:
            command = [sys.executable, '-m', 'jav128.cli', *args]
            result = subprocess.run(command, text=True, capture_output=True)
            assert result.returncode == 0, result.stderr
            log.append({'command': command, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        assert recovered.read_bytes() == Path('data/inputs/text_utf8.txt').read_bytes()
        assert encrypted.read_bytes()[4] == 2
        assert json.loads(stats.read_text())['mode'] == mode
    wrong = root / 'wrong.txt'
    wrong.write_bytes(b'wrong')
    original_stats = stats.read_bytes()
    try:
        result = subprocess.run([sys.executable, '-m', 'jav128.cli', 'analyze', '--input', str(encrypted),
                                 '--plaintext', str(wrong), '--output', str(stats), '--key-hex', key],
                                text=True, capture_output=True)
        assert result.returncode == 2 and 'does not match' in result.stderr
        assert stats.read_bytes() == original_stats
        log.append({'case': 'analyze_wrong_plaintext', 'exit_code': result.returncode, 'stderr': result.stderr,
                    'output_preserved': True})
    finally:
        wrong.unlink()
    Path('data/results/cli_verification.json').write_text(json.dumps(log, indent=2) + '\n')
    print('15 successful CLI commands and one negative analyze check passed.')


if __name__ == '__main__':
    main()
