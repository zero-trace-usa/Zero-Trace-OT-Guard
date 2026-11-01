"""Run using the installed wheel's clean Python, without pytest or source imports."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from pcap_fixture import capture


def main():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        evidence = root/'evidence'
        evidence.mkdir()
        pdu = b'\x06\x00\x01\x00\x02'
        capture(evidence/'capture.pcap', [(False,pdu),(True,pdu)])
        policy = root/'policy.json'
        policy.write_text(json.dumps({'modbus_write_allowlist': []}))
        output = root/'report'
        subprocess.run([sys.executable, '-m', 'otguard', 'analyze', '--input', str(evidence),
                        '--output', str(output), '--write-policy', str(policy)], check=True)
        result = json.loads((output/'report.json').read_text())
        assert result['summary'] == {'observed_assets':2,'flows':2,'findings':1}
        assert len(result['write_operations']) == 1
        assert result['write_operations'][0]['function_code'] == 6
        assert result['write_operations'][0]['authorized'] is False
        assert 'Unexpected Modbus write request' in (output/'report.html').read_text()
        assert 'Write Single Register' in (output/'write_operations.csv').read_text()
        version = subprocess.run([sys.executable, '-m', 'otguard', '--version'],
                                 capture_output=True, text=True, check=True).stdout.strip()
        assert version == 'Zero-Trace OT Guard 1.0.0rc6'
        print('Installed-wheel Modbus detection, reports and version verified')


if __name__ == '__main__':
    main()
