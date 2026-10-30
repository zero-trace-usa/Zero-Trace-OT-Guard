import argparse
import json
from pathlib import Path
from . import __version__
from .core import rows_csv,parse_pcap,assess,write_report
from .active import connect_checks, sign_approval

def main(argv=None):
    p=argparse.ArgumentParser(prog='otguard',description='Zero-Trace OT Guard — passive by default')
    p.add_argument('--version', action='version', version=f'Zero-Trace OT Guard {__version__}')
    sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('analyze', formatter_class=argparse.ArgumentDefaultsHelpFormatter, help='Offline CSV/PCAP analysis; never sends network traffic')
    a.add_argument('--input',required=True,help='Directory with flows.csv or capture.pcap')
    a.add_argument('--output',default='reports',help='Directory for HTML, JSON and CSV reports')
    a.add_argument('--max-packets',type=int,default=500000,help='PCAP packet processing cap (1–1000000); not used for CSV')
    b=sub.add_parser('active-check', formatter_class=argparse.ArgumentDefaultsHelpFormatter, help='Approval-gated TCP-connect only (dry-run by default)')
    b.add_argument('--approval',required=True,help='Path to HMAC-signed approval JSON');b.add_argument('--target',action='append',required=True,help='Exact approved IP address; repeat for multiple targets')
    b.add_argument('--port',type=int,action='append',required=True,help='Approved TCP port; repeat for multiple ports')
    b.add_argument('--ack-authorized',action='store_true',help='Acknowledge separately obtained authorization');b.add_argument('--execute',action='store_true',help='Execute the reviewed plan; omission produces an offline plan')
    b.add_argument('--output',default='active-results.json',help='JSON plan or execution result file')
    b.add_argument('--plan-id', help='SHA-256 plan identifier from the reviewed dry-run; required with --execute')
    b.add_argument('--stop-file',help='Existing file requests cooperative stop; inspect stale stops before execution')
    b.add_argument('--audit-file',default='active-audit.jsonl',help='Append-only JSONL execution audit destination')
    c=sub.add_parser('sign-approval',help='Sign an approval file using OTGUARD_APPROVAL_KEY; run only by authorized approver')
    c.add_argument('--approval',required=True,help='Approval JSON to sign in place using OTGUARD_APPROVAL_KEY')
    args=p.parse_args(argv)
    try:
        if args.command=='sign-approval':
            sign_approval(args.approval)
            print('Approval signed')
        elif args.command=='analyze':
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
            result=connect_checks(args.approval,args.target,args.port,args.ack_authorized,args.execute,args.stop_file,args.audit_file,args.plan_id)
            Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
            print(json.dumps(result,indent=2))
            if result['mode'] == 'interrupted':
                return 3
        return 0
    except (ValueError,PermissionError,OSError,AssertionError) as exc:
        p.exit(2,'Error: '+str(exc)+'\n')
