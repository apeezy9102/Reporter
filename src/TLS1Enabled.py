import os
import xml.etree.ElementTree as ET
import csv

from argparse import *


# Argument Parser 
def tls1ArgumentParser():
    __desc__="This tool creates a csv file of all TLS version 1.0 findings in a .nessus file\r\nAppend this to your supporting material"
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=__desc__
    )
    return parser


# Argument Flags
def tls1ArgumentOptions(parser):
    parser.add_argument('-i', metavar='FILE', help='Nessus export file', required=True)
    parser.add_argument('-n', metavar='NAME', default='Report_Tables', help='Name for output file names (default TLS1_Report_Tables)')

    args = parser.parse_args()
    return args


# Colours used for terminal output
class colours:
    HEADER = '\033[95m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    INFO = '\033[94m'
    PASS = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'


# Check if this is a .nessus file
def validateInput(parser, args):
    if not os.path.isfile(args.i) or not args.i.endswith('.nessus'):
        parser.print_help()
        print(colours.FAIL + '\n[!] Nessus output file required' + colours.END)
        exit(1)
    else:
        return "validated"


def tls1Supported(args):    
    tlsFindings = []
    root = ET.parse(args.i).getroot()
    report = root.find('Report')
    for host in report.findall('ReportHost'):
        name = host.get('name')
        for item in host.findall('ReportItem'):
            if 'TLS Version 1.0 Protocol Detection' in item.get('pluginName'):
                tls1Enabled = "TLS Version 1.0 Enabled"
                port = item.get('port')
                service = item.get('svc_name')
                tls1Finding = {"Host": name, "Port": port, "Service": service, "TLS Version": tls1Enabled}
                tlsFindings.append(tls1Finding)
    return tlsFindings


def exportTLS2Csv(args, tlsFindings):
    filename = '{}_{}.csv'.format("TLS1", args.n)

    with open(filename, 'w', newline='') as f: #Create Csv file
        fieldNames = ['Host', 'Port', 'Service', 'TLS Version'] # Csv headers
        writer = csv.DictWriter(f, fieldnames=fieldNames)        
        writer.writeheader()
        for i in tlsFindings:
            writer.writerow(i) # Write the findings to a row


if __name__ == "__main__":
    parser = tls1ArgumentParser()
    args = tls1ArgumentOptions(parser)
    if validateInput(parser, args) == "validated":
        tlsFindings = tls1Supported(args)
        exportTLS2Csv(args, tlsFindings)


