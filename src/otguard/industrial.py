"""Offline protocol dissection through TShark; no live capture or device access."""
import ipaddress
import json
# Required offline TShark CLI; commands use an argument list without a shell.
import subprocess  # nosec B404
import tempfile
from pathlib import Path

from .core import MAX_PCAP_BYTES, MAX_CSV_BYTES

WRITES = {5: 'Write Single Coil', 6: 'Write Single Register',
          15: 'Write Multiple Coils', 16: 'Write Multiple Registers',
          21: 'Write File Record', 22: 'Mask Write Register',
          23: 'Read/Write Multiple Registers'}


def load_policy(path):
    """Exact IP sources with optional exact destinations; empty rules deny all."""
    path = Path(path)
    if path.stat().st_size > MAX_CSV_BYTES:
        raise ValueError('Write policy exceeds 20 MiB')
    try:
        policy = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(policy, dict) or set(policy) != {'modbus_write_allowlist'}:
            raise ValueError('Expected modbus_write_allowlist only')
        rules = policy['modbus_write_allowlist']
        if not isinstance(rules, list):
            raise ValueError('Allowlist must be a list')
        normalized = []
        for rule in rules:
            if not isinstance(rule, dict) or not {'source'} <= set(rule) <= {'source', 'destinations'}:
                raise ValueError('Each rule needs source and optional destinations')
            if not isinstance(rule['source'], str):
                raise ValueError('source must be an exact IP address string')
            source = str(ipaddress.ip_address(rule['source']))
            destinations = rule.get('destinations')
            if 'destinations' in rule:
                if not isinstance(destinations, list) or not destinations:
                    raise ValueError('destinations must be a nonempty list of exact IP addresses')
                if not all(isinstance(ip, str) for ip in destinations):
                    raise ValueError('destinations must contain IP address strings')
                destinations = [str(ipaddress.ip_address(ip)) for ip in destinations]
            normalized.append({'source': source, 'destinations': destinations})
        return normalized
    except (TypeError, KeyError) as exc:
        raise ValueError('Invalid write policy') from exc


def analyze_writes(path, policy_path, max_packets=500000, decode_ports=()):
    """Return each decoded Modbus write request, retaining frame/PDU provenance."""
    rules = load_policy(policy_path)
    path = Path(path).resolve()
    if path.stat().st_size > MAX_PCAP_BYTES:
        raise ValueError('PCAP exceeds 256 MiB safety limit')
    if not 1 <= max_packets <= 1000000:
        raise ValueError('max_packets must be between 1 and 1000000')
    # JSON preserves multiple Modbus PDUs per frame; flat field arrays cannot
    # reliably associate function codes with the matching request/response PDU.
    server_ports = {502, *decode_ports}
    command = ['tshark', '-n', '-r', str(path), '-c', str(max_packets),
               '-Y', 'mbtcp', '-T', 'json', '--no-duplicate-keys']
    for port in decode_ports:
        if not 1 <= port <= 65535:
            raise ValueError('Modbus decode port must be between 1 and 65535')
    command += ['-o', 'mbtcp.tcp.port:' + ','.join(str(p) for p in sorted(server_ports))]
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            # Fixed executable, absolute capture path and numeric options only; shell=False.
            completed = subprocess.run(command, stdout=output, stderr=errors,  # nosec B603
                                       timeout=120, check=False)  # no shell or live interface
            errors.seek(0)
            diagnostic = errors.read(8192).decode('utf-8', errors='replace').strip()
            if completed.returncode:
                raise ValueError('TShark failed: ' + diagnostic)
            if output.tell() > MAX_PCAP_BYTES:
                raise ValueError('TShark JSON exceeds 256 MiB safety limit')
            output.seek(0)
            packets = json.load(output)
    except FileNotFoundError as exc:
        raise ValueError('TShark is required for --write-policy; install tshark and add it to PATH') from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError('TShark exceeded 120 second analysis limit') from exc
    except json.JSONDecodeError as exc:
        raise ValueError('Invalid TShark JSON output') from exc
    writes = []
    decoded = 0
    ambiguous = 0
    malformed = 0
    other_requests = 0
    unsupported_context = 0
    unsupported_protocol = 0
    for packet in packets:
        layers = packet['_source']['layers']
        if '_ws.malformed' in layers:
            malformed += 1
            continue
        tcp = layers.get('tcp', {})
        # Multiple IP/TCP layers can describe tunnels; never associate a decoded
        # command with an arbitrary outer endpoint. Leave that context unassessed.
        if not isinstance(tcp, dict) or any(not isinstance(layers[k], dict) for k in ('ip', 'ipv6') if k in layers):
            unsupported_context += 1
            continue
        sport, dport = int(tcp.get('tcp.srcport', 0)), int(tcp.get('tcp.dstport', 0))
        network = layers.get('ip', layers.get('ipv6', {}))
        prefix = 'ip' if 'ip' in layers else 'ipv6'
        source, destination = network.get(prefix+'.src'), network.get(prefix+'.dst')
        headers = layers.get('mbtcp', [])
        if isinstance(headers, dict):
            headers = [headers]
        # Some dissector versions expose Modbus fields even when MBAP's
        # protocol identifier is nonzero. Require the actual header identifier.
        # Mixed/unknown headers leave the whole frame unassessed.
        if not headers or any(header.get('mbtcp.prot_id') != '0' for header in headers):
            unsupported_protocol += 1
            continue
        pdus = layers.get('modbus', [])
        if isinstance(pdus, dict):
            pdus = [pdus]
        for index, pdu in enumerate(pdus, 1):
            decoded += 1
            if (sport in server_ports) == (dport in server_ports):
                ambiguous += 1
                continue
            if sport in server_ports:
                continue
            # request_frame means this PDU is a response. Exception replies are
            # excluded too. An unanswered request need not have response_frame.
            if 'modbus.request_frame' in pdu or 'modbus.exception_code' in pdu:
                continue
            code = int(pdu.get('modbus.func_code', '0'))
            if code not in WRITES or not source or not destination:
                other_requests += 1
                continue
            source = str(ipaddress.ip_address(source))
            destination = str(ipaddress.ip_address(destination))
            allowed = any(r['source'] == source and
                          (r['destinations'] is None or destination in r['destinations']) for r in rules)
            writes.append({'frame': layers['frame']['frame.number'], 'pdu': index,
                           'source': source, 'destination': destination,
                           'protocol': 'Modbus/TCP', 'function_code': code,
                           'operation': WRITES[code], 'authorized': allowed})
    return writes, {'engine': 'TShark', 'evaluated_allowlist': rules,
                    'unassessed_context_frames': unsupported_context,
                    'unassessed_protocol_frames': unsupported_protocol,
                    'other_or_unassessed_requests': other_requests, 'decoded_modbus_pdus': decoded,
                    'write_requests': len(writes),
                    'ambiguous_direction_pdus': ambiguous, 'malformed_frames': malformed, 'packet_limit': max_packets,
                    'decode_as_tcp_ports': list(decode_ports),
                    'warnings': [diagnostic] if diagnostic else [],
                    'coverage': 'Request direction requires exactly one configured server port (502 plus explicit overrides). Modbus/TCP functions 5, 6, 15, 16, 21, 22, 23 only. '
                    'Captured requests do not prove successful writes. Encrypted, '
                    'undecoded, malformed, multiply encapsulated or missing traffic is not assessed. '
                    'Processing stops at the packet cap; absence of detected writes is not proof of absence.'}


def add_write_findings(result, writes, metadata):
    result['write_operations'] = writes
    result['write_analysis'] = metadata
    for write in writes:
        if not write['authorized']:
            result['findings'].append({
                'type': 'Unexpected Modbus write request', 'severity': 'Review',
                'asset': write['destination'],
                'evidence': f"Frame {write['frame']} PDU {write['pdu']}: {write['source']} -> "
                            f"{write['destination']}; function {write['function_code']} ({write['operation']})",
                'recommendation': 'Verify the source and destination against the approved write policy; '
                                  'a captured request does not establish successful execution.'})
    result['summary']['findings'] = len(result['findings'])
    result['limitations'].append(metadata['coverage'])
