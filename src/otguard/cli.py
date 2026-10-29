import argparse
import json
from pathlib import Path
from .core import rows_csv,parse_pcap,assess,write_report
from .active import connect_checks

def main(argv=None):
    p=argparse.ArgumentParser(prog='otguard',description='Zero-Trace OT Guard — passive by default')
    sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('analyze',help='Offline CSV/PCAP analysis; never sends network traffic')
    a.add_argument('--input',required=True,help='Directory with flows.csv or capture.pcap')
    a.add_argument('--output',default='reports')
    a.add_argument('--max-packets',type=int,default=500000)
    b=sub.add_parser('active-check',help='Approval-gated TCP-connect only (dry-run by default)')
    b.add_argument('--approval',required=True);b.add_argument('--target',action='append',required=True)
    b.add_argument('--port',type=int,action='append',required=True)
    b.add_argument('--ack-authorized',action='store_true');b.add_argument('--execute',action='store_true')
    b.add_argument('--output',default='active-results.json')
    args=p.parse_args(argv)
    try:
        if args.command=='analyze':
            folder=Path(args.input)
            if (folder/'flows.csv').exists():flows=rows_csv(folder/'flows.csv');meta={'source':'CSV'}
            elif (folder/'capture.pcap').exists():flows,meta=parse_pcap(folder/'capture.pcap',args.max_packets)
            else:raise ValueError('Expected flows.csv or capture.pcap in input directory')
            get=lambda name:rows_csv(folder/name) if (folder/name).exists() else []
            result=assess(flows,get('assets.csv'),get('advisories.csv'),get('rules.csv'))
            result['evidence_metadata']=meta
            write_report(result,args.output)
            print(json.dumps({'output':args.output,'summary':result['summary']},indent=2))
        else:
            result=connect_checks(args.approval,args.target,args.port,args.ack_authorized,args.execute)
            Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
            print(json.dumps(result,indent=2))
        return 0
    except (ValueError,PermissionError,OSError,AssertionError) as exc:
        p.exit(2,'Error: '+str(exc)+'\n')
