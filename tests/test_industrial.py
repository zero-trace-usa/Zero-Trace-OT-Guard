"""Actual TShark regression captures, generated offline without sockets."""
import json
import shutil
import struct
import pytest
from otguard.industrial import analyze_writes, load_policy, add_write_findings, WRITES
from otguard.core import assess, write_report
from otguard.cli import main


from pcap_fixture import capture


def policy(tmp_path, rules):
    path = tmp_path/'policy.json'
    path.write_text(json.dumps({'modbus_write_allowlist': rules}))
    return path


@pytest.fixture
def tshark():
    if not shutil.which('tshark'):
        pytest.skip('TShark integration requires installed tshark')


@pytest.mark.parametrize('rules,allowed', [([], False),
    ([{'source':'10.0.0.1'}], True),
    ([{'source':'10.0.0.1','destinations':['10.0.0.2']}], True),
    ([{'source':'10.0.0.1','destinations':['10.0.0.3']}], False),
    ([{'source':'10.0.0.9'}], False)])
def test_real_request_reply_and_policy(tmp_path, tshark, rules, allowed):
    pdu = b'\x06\x00\x01\x00\x02'
    pcap = capture(tmp_path/'capture.pcap', [(False,pdu),(True,pdu)])
    writes, meta = analyze_writes(pcap, policy(tmp_path,rules))
    assert len(writes)==1
    assert writes[0]['frame']=='1' and writes[0]['authorized'] is allowed
    result = assess([])
    add_write_findings(result,writes,meta)
    assert result['summary']['findings']==(0 if allowed else 1)
    write_report(result,tmp_path/'reports')
    assert 'Write Single Register' in (tmp_path/'reports/report.html').read_text()
    assert 'authorized' in (tmp_path/'reports/write_operations.csv').read_text()


@pytest.mark.parametrize('code,payload', [
    (5,b'\x00\x01\xff\x00'),(6,b'\x00\x01\x00\x02'),
    (15,b'\x00\x01\x00\x01\x01\x01'),
    (16,b'\x00\x01\x00\x01\x02\x00\x02'),
    (21,b'\x09\x06\x00\x01\x00\x00\x00\x01\x00\x02'),
    (22,b'\x00\x01\xff\x00\x00\xff'),
    (23,b'\x00\x01\x00\x01\x00\x01\x00\x01\x02\x00\x02')])
def test_supported_write_commands(tmp_path,tshark,code,payload):
    pcap=capture(tmp_path/'capture.pcap',[(False,bytes([code])+payload)])
    writes,_=analyze_writes(pcap,policy(tmp_path,[]))
    assert [w['function_code'] for w in writes]==[code]
    assert writes[0]['operation']==WRITES[code]


def test_read_exception_and_orphan_reply_excluded(tmp_path,tshark):
    pcap=capture(tmp_path/'capture.pcap',[(False,b'\x03\x00\x00\x00\x01'),
                 (True,b'\x86\x02'),(True,b'\x06\x00\x01\x00\x02')])
    assert analyze_writes(pcap,policy(tmp_path,[]))[0]==[]


def test_nonstandard_port_requires_explicit_decode(tmp_path,tshark):
    pdu=b'\x06\x00\x01\x00\x02'
    pcap=capture(tmp_path/'capture.pcap',[(False,pdu),(True,pdu)],1502)
    pol=policy(tmp_path,[])
    assert analyze_writes(pcap,pol)[0]==[]
    assert len(analyze_writes(pcap,pol,decode_ports=[1502])[0])==1


def test_multiple_pdus_and_packet_cap(tmp_path,tshark):
    # Two complete MBAP PDUs in one TCP segment, not two flat field arrays.
    pdu=b'\x06\x00\x01\x00\x02'
    second=struct.pack('!HHHB',2,0,6,1)+pdu
    pcap=capture(tmp_path/'capture.pcap',[(False,pdu+second)])
    data=bytearray(pcap.read_bytes())
    # First MBAP length must describe only its own PDU.
    struct.pack_into('!H',data,24+16+14+20+20+4,6)
    pcap.write_bytes(data)
    writes,meta=analyze_writes(pcap,policy(tmp_path,[]),max_packets=1)
    assert len(writes)==2
    assert [w['pdu'] for w in writes]==[1,2]
    assert meta['packet_limit']==1


@pytest.mark.parametrize('value',[{}, {'modbus_write_allowlist':None},
    {'modbus_write_allowlist':[{'source':'host.example'}]},
    {'modbus_write_allowlist':[{'source':'10.0.0.1','destinations':[]}]},
    {'modbus_write_allowlist':[{'source':'10.0.0.1','destination':'10.0.0.2'}]}])
def test_invalid_policy(tmp_path,value):
    path=tmp_path/'bad.json';path.write_text(json.dumps(value))
    with pytest.raises(ValueError):load_policy(path)


def test_missing_tshark(tmp_path,monkeypatch):
    monkeypatch.setenv('PATH','')
    pcap=capture(tmp_path/'capture.pcap',[])
    with pytest.raises(ValueError,match='TShark is required'):
        analyze_writes(pcap,policy(tmp_path,[]))


def test_cli_refuses_csv_write_analysis(tmp_path):
    (tmp_path/'flows.csv').touch()
    with pytest.raises(SystemExit) as exc:
        main(['analyze','--input',str(tmp_path),'--write-policy','unused.json'])
    assert exc.value.code==2


@pytest.mark.parametrize('result,error', [('failure','TShark failed'),('invalid','Invalid TShark JSON')])
def test_dissector_failure_is_not_a_clean_report(tmp_path,monkeypatch,result,error):
    from types import SimpleNamespace
    import otguard.industrial as industrial
    def run(command,stdout,stderr,**kwargs):
        assert command[:3]==['tshark','-n','-r']
        assert '-i' not in command and '-w' not in command
        assert kwargs['timeout']==120
        stdout.write(b'not json' if result=='invalid' else b'[]')
        stderr.write(b'dissector error' if result=='failure' else b'')
        return SimpleNamespace(returncode=1 if result=='failure' else 0)
    monkeypatch.setattr(industrial.subprocess,'run',run)
    pcap=capture(tmp_path/'capture.pcap',[])
    with pytest.raises(ValueError,match=error):
        analyze_writes(pcap,policy(tmp_path,[]))


def test_dissector_timeout(tmp_path,monkeypatch):
    import otguard.industrial as industrial
    def run(*args,**kwargs):
        raise industrial.subprocess.TimeoutExpired('tshark',120)
    monkeypatch.setattr(industrial.subprocess,'run',run)
    pcap=capture(tmp_path/'capture.pcap',[])
    with pytest.raises(ValueError,match='120 second'):
        analyze_writes(pcap,policy(tmp_path,[]))


def test_cli_real_capture(tmp_path,tshark):
    capture(tmp_path/'capture.pcap',[(False,b'\x06\x00\x01\x00\x02')])
    out=tmp_path/'output'
    assert main(['analyze','--input',str(tmp_path),'--output',str(out),
                 '--write-policy',str(policy(tmp_path,[]))])==0
    report=json.loads((out/'report.json').read_text())
    assert report['summary']=={'observed_assets':2,'flows':1,'findings':1}
    assert report['write_operations'][0]['function_code']==6
    assert report['write_analysis']['evaluated_allowlist']==[]


@pytest.mark.parametrize('value', [
    {'modbus_write_allowlist':[{'source':True}]},
    {'modbus_write_allowlist':[{'source':'10.0.0.1','destinations':[123]}]},
    {'modbus_write_allowlist':[{'source':'10.0.0.0/24'}]},
    {'modbus_write_allowlist':[{'source':'10.0.0.1','destinations':None}]}])
def test_policy_rejects_implicit_or_broad_addresses(tmp_path,value):
    path=tmp_path/'policy.json';path.write_text(json.dumps(value))
    with pytest.raises(ValueError):load_policy(path)


def test_packet_limit_restricts_actual_dissection(tmp_path,tshark):
    pdu=b'\x06\x00\x01\x00\x02'
    pcap=capture(tmp_path/'capture.pcap',[(False,pdu),(False,pdu)])
    pol=policy(tmp_path,[])
    assert len(analyze_writes(pcap,pol,max_packets=1)[0])==1
    assert len(analyze_writes(pcap,pol,max_packets=2)[0])==2


def test_ambiguous_server_ports_are_not_called_writes(tmp_path,tshark):
    pcap=capture(tmp_path/'capture.pcap',[(False,b'\x06\x00\x01\x00\x02')])
    writes,meta=analyze_writes(pcap,policy(tmp_path,[]),decode_ports=[12345])
    assert writes==[] and meta['ambiguous_direction_pdus']==1


def test_malformed_capture_fails_without_report(tmp_path,tshark):
    (tmp_path/'capture.pcap').write_bytes(b'not a capture')
    with pytest.raises(ValueError,match='TShark failed'):
        analyze_writes(tmp_path/'capture.pcap',policy(tmp_path,[]))


def test_non_modbus_payload_on_modbus_port(tmp_path,tshark):
    pcap=capture(tmp_path/'capture.pcap',[(False,b'\x06\x00\x01\x00\x02')])
    data=bytearray(pcap.read_bytes())
    # MBAP protocol identifier must be zero for Modbus/TCP.
    struct.pack_into('!H',data,24+16+14+20+20+2,1)
    pcap.write_bytes(data)
    assert analyze_writes(pcap,policy(tmp_path,[]))[0]==[]


def test_multiple_ip_layers_are_unassessed(tmp_path,monkeypatch):
    import otguard.industrial as industrial
    from types import SimpleNamespace
    packet={'_source':{'layers':{
        'frame':{'frame.number':'1'},
        'ip':[{'ip.src':'10.0.0.9','ip.dst':'10.0.0.8'},
              {'ip.src':'10.0.0.1','ip.dst':'10.0.0.2'}],
        'tcp':{'tcp.srcport':'12345','tcp.dstport':'502'},
        'modbus':{'modbus.func_code':'6'}}}}
    def run(command,stdout,stderr,**kwargs):
        stdout.write(json.dumps([packet]).encode())
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(industrial.subprocess,'run',run)
    pcap=capture(tmp_path/'capture.pcap',[])
    writes,meta=analyze_writes(pcap,policy(tmp_path,[]))
    assert writes==[] and meta['unassessed_context_frames']==1
