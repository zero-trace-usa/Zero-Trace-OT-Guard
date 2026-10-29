"""Offline evidence analysis. No network operations in this module."""
import csv
import os
import ipaddress
import json
import struct
from collections import Counter
from pathlib import Path
from html import escape

PORTS = {502:'Modbus/TCP',44818:'EtherNet/IP',2222:'EtherNet/IP I/O',20000:'DNP3',102:'S7comm/ISO-on-TCP',4840:'OPC UA',47808:'BACnet/IP',2404:'IEC 60870-5-104',1883:'MQTT',8883:'MQTT/TLS',161:'SNMP',80:'HTTP',443:'HTTPS',22:'SSH',3389:'RDP',445:'SMB'}
FIELDS = ('src_ip','dst_ip','protocol','src_port','dst_port','packets','bytes')

MAX_CSV_BYTES = 20 * 1024 * 1024
MAX_CSV_ROWS = 100000
MAX_PCAP_BYTES = 256 * 1024 * 1024

def rows_csv(path):
    if Path(path).stat().st_size > MAX_CSV_BYTES:
        raise ValueError('CSV file exceeds 20 MiB safety limit')
    with open(path, encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        result=[]
        for row in reader:
            if len(result) >= MAX_CSV_ROWS:
                raise ValueError('CSV row limit exceeded')
            result.append(row)
        return result

def parse_pcap(path, max_packets=500000):
    """Classic PCAP Ethernet/IPv4 TCP+UDP metadata only. No payload retention."""
    if Path(path).stat().st_size > MAX_PCAP_BYTES:
        raise ValueError('PCAP exceeds 256 MiB safety limit')
    if not 1 <= max_packets <= 1000000:
        raise ValueError('max_packets must be between 1 and 1000000')
    flows=Counter(); warnings=[]; count=0; skipped=0
    with open(path,'rb') as f:
        hdr=f.read(24)
        if len(hdr)!=24: raise ValueError('Truncated PCAP header')
        magic=hdr[:4]
        if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'): endian='<'
        elif magic in (b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'): endian='>'
        else: raise ValueError('Unsupported capture format: classic PCAP required (not PCAPNG)')
        link=struct.unpack(endian+'I',hdr[20:24])[0]
        if link!=1: raise ValueError('Only Ethernet (DLT_EN10MB) PCAP supported')
        while count < max_packets:
            ph=f.read(16)
            if not ph: break
            if len(ph)!=16: warnings.append('Truncated packet header'); break
            _,_,incl,orig=struct.unpack(endian+'IIII',ph)
            if incl>16*1024*1024: raise ValueError('Oversized PCAP record')
            b=f.read(incl)
            if len(b)!=incl: warnings.append('Truncated packet data'); break
            count+=1
            if len(b)<14:
                skipped+=1; continue
            off=14; eth=struct.unpack('!H',b[12:14])[0]
            while eth in (0x8100,0x88a8,0x9100) and len(b)>=off+4:
                eth=struct.unpack('!H',b[off+2:off+4])[0]; off+=4
            if eth!=0x0800 or len(b)<off+20: continue
            ip=b[off:]; version=ip[0]>>4; ihl=(ip[0]&15)*4
            if version!=4 or ihl<20 or len(ip)<ihl:
                skipped+=1; continue
            total_length=struct.unpack('!H',ip[2:4])[0]
            if total_length<ihl or total_length>len(ip):
                skipped+=1; continue
            ip=ip[:total_length]
            if struct.unpack('!H',ip[6:8])[0]&0x3fff: continue
            proto=ip[9]
            minimum=20 if proto==6 else 8
            if proto not in (6,17) or len(ip)<ihl+minimum:
                skipped+=1; continue
            sport,dport=struct.unpack('!HH',ip[ihl:ihl+4])
            src=str(ipaddress.IPv4Address(ip[12:16])); dst=str(ipaddress.IPv4Address(ip[16:20]))
            flows[(src,dst,'TCP' if proto==6 else 'UDP',sport,dport)]+=1
        if count>=max_packets: warnings.append('Packet limit reached; capture may be incomplete')
    result=[dict(zip(FIELDS[:5],k),packets=n,bytes=0) for k,n in sorted(flows.items())]
    return result,{'packets_processed':count,'packets_skipped_or_malformed':skipped,'warnings':warnings,'capture_note':'bytes not aggregated for PCAP; metadata-only parsing'}

def normalize_flow(row):
    a={k:str(row.get(k,'')).strip() for k in FIELDS}
    for key in ('src_ip','dst_ip'): ipaddress.ip_address(a[key])
    a['protocol']=a['protocol'].upper()
    if a['protocol'] not in ('TCP','UDP'): raise ValueError('Only TCP/UDP flow rows supported')
    for key in ('src_port','dst_port'):
        a[key]=int(a[key]); 
        if not 0<=a[key]<=65535: raise ValueError('Port out of range')
    for key in ('packets','bytes'):
        a[key]=int(a[key] or 0)
        if a[key]<0: raise ValueError('Negative flow metric')
    a['service']=PORTS.get(a['dst_port'],'Unknown')
    return a

def assess(flows, assets=None, advisories=None, rules=None):
    assets=assets or []; advisories=advisories or []; rules=rules or []
    normalized=[normalize_flow(f) for f in flows]
    seen={ip for f in normalized for ip in (f['src_ip'],f['dst_ip'])}
    inventory={a['ip'].strip():dict(a) for a in assets if a.get('ip')}
    for ip in seen: inventory.setdefault(ip,{'ip':ip,'vendor':'','product':'','version':'','zone':'Unknown'})
    findings=[]
    for f in normalized:
        for r in rules:
            if not r.get('src_zone') or not r.get('dst_zone'): continue
            if inventory[f['src_ip']].get('zone')==r['src_zone'] and inventory[f['dst_ip']].get('zone')==r['dst_zone']:
                port=r.get('dst_port','*').strip()
                if port not in ('*',str(f['dst_port'])): continue
                if r.get('action','').lower()=='deny':
                    findings.append({'type':'Observed zone policy conflict','severity':'Review','asset':f['dst_ip'],'evidence':f"{f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} {f['protocol']}",'recommendation':'Validate approved conduit and enforcement logs; observed traffic alone does not prove bypass.'})
    for a in inventory.values():
        for v in advisories:
            if not v.get('vendor') or not v.get('product'): continue
            if a.get('vendor','').casefold()==v['vendor'].casefold() and a.get('product','').casefold()==v['product'].casefold():
                match=(not v.get('version') or a.get('version','')==v['version'])
                if match:
                    findings.append({'type':'Potential advisory match','severity':'Review','asset':a['ip'],'evidence':v.get('advisory_id','Unspecified')+' (inventory-based; not confirmed vulnerable)','recommendation':'Verify firmware, affected versions, vendor mitigations and compensating controls.'})
    return {'summary':{'observed_assets':len(inventory),'flows':len(normalized),'findings':len(findings)},'assets':sorted(inventory.values(),key=lambda a:a['ip']),'flows':normalized,'findings':findings,'limitations':['Passive observation does not prove absence of devices, services or vulnerabilities.','Port-based protocol identification is indicative, not a protocol decoder.','No active OT protocol requests or exploitation performed.']}

def csv_safe(value):
    text=str(value) if value is not None else ''
    if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
        return "'"+text
    return text

def write_report(result,out):
    out=Path(out); out.mkdir(parents=True,exist_ok=True)
    (out/'report.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    for name,items in [('assets',result['assets']),('flows',result['flows']),('findings',result['findings'])]:
        with (out/(name+'.csv')).open('w',newline='',encoding='utf-8') as f:
            keys=list(dict.fromkeys(k for item in items for k in item))
            w=csv.DictWriter(f,fieldnames=keys); w.writeheader(); w.writerows([{k:csv_safe(v) for k,v in item.items()} for item in items])
    def table(items):
        if not items:return '<p>No entries.</p>'
        keys=list(dict.fromkeys(k for x in items for k in x))
        return '<table><thead><tr>'+''.join('<th>'+escape(k)+'</th>' for k in keys)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+escape(str(x.get(k,'')))+'</td>' for k in keys)+'</tr>' for x in items)+'</tbody></table>'
    html="""<!doctype html><html lang="en"><meta charset="utf-8"><title>Zero-Trace OT Guard Report</title><style>body{font:15px system-ui;max-width:1150px;margin:3rem auto;color:#182633;padding:0 1rem}h1{color:#125b65}table{border-collapse:collapse;width:100%;font-size:13px;margin:1rem 0}th,td{padding:8px;border:1px solid #ccd6db;text-align:left;overflow-wrap:anywhere}th{background:#edf3f5}p{line-height:1.6}</style><h1>Zero-Trace OT Guard</h1><p>Evidence-based offline assessment • Not a certification or proof of vulnerability</p>"""
    for heading,content in [('Summary',[result['summary']]),('Findings',result['findings']),('Assets',result['assets']),('Flows',result['flows'])]:html+='<h2>'+heading+'</h2>'+table(content)
    html+='<h2>Limitations</h2><ul>'+''.join('<li>'+escape(x)+'</li>' for x in result['limitations'])+'</ul></html>'
    (out/'report.html').write_text(html,encoding='utf-8')
