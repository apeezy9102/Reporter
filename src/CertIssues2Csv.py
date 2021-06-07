import os
import xml.etree.ElementTree as ET
import csv
import time
import re

from argparse import *


# Argument Parser 
def cert2rArgumentParser():
    __desc__="This tool creates a csv file of untrusted SSL/TLS certificate findings in a .nessus file\r\nAppend this to your supporting material"
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=__desc__
    )
    return parser


def cert2rArgumentOptions(parser):
    # Argument Flags
    parser.add_argument('-i', metavar='FILE', help='Nessus export file', required=True)
    parser.add_argument('-n', metavar='NAME', default='Report_Tables', help='Name for output file names (default Untrusted_Certificates)')

    args = parser.parse_args()
    return args


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

# Regex Patterns
issue_regexp = re.compile("signed by an unknown\s^certificate authority", re.MULTILINE) # Pattern to find the text containing unknown CA
CA_Issuer_regexp = re.compile("(?<=-Issuer  : ).+") # Pattern for the certificate issuer
certExpiry_regexp = re.compile("(?<=-Not After :).+") # Pattern for the expiry date
subjectExpiry_regexp = re.compile("((?<=-Subject : ).+)|((?<=-Subject   : ).+)") # Pattern to the certificate's subject value
certName_regexp = re.compile("(?<=CN=).+") # Pattern for getting the CN value from the certificate

#args = "..\Heckfield_Management_vv22gb.nessus"

def untrustedCerts(args):
    certFindings = []
    root = ET.parse(args.i).getroot()
    report = root.find('Report')
    for host in report.findall('ReportHost'):
        name = host.get('name')
        for item in host.findall('ReportItem'):
            if 'SSL Certificate Cannot Be Trusted' in item.get('pluginName'):
                output = item.find('plugin_output').text
                issue = issue_regexp.search(output)

                #print(subject_match, name, item.get('port'))
                if issue is not None:
                    subject_match = subjectExpiry_regexp.search(output).group(0)
                    unknownCA_unsorted = (issue.group(0)).replace('\n',' ') # Get the matched text all on one line
                    unknownCA = unknownCA_unsorted.replace('signed', 'Signed') # Capitalise first word "signed" 
                    ca_issuer = CA_Issuer_regexp.search(output).group(0)
                    certName_regexp.search(subject_match)
                    if certName_regexp.search(subject_match) is not None:
                        certName = certName_regexp.search(subject_match).group(0)
                        port = item.get('port')
                        certFinding = {"Host": name, "Port": port, "Issue": unknownCA, "Reason": ca_issuer, "Certificate Name": certName }
                        certFindings.append(certFinding)
                    else:
                        certName = subject_match
                        port = item.get('port')
                        certFinding = {"Host": name, "Port": port, "Issue": unknownCA, "Reason": ca_issuer, "Certificate Name": certName }
                        certFindings.append(certFinding)
                elif 'expired' in output:
                    subject_match = subjectExpiry_regexp.search(output).group(0)
                    certExpiry = certExpiry_regexp.search(output).group(0)
                    if certName_regexp.search(subject_match) is not None:
                        certName = certName_regexp.search(subject_match).group(0)
                        port = item.get('port')
                        certFinding = {"Host": name, "Port": port, "Issue": "Certificate expired", "Reason": certExpiry, "Certificate Name": certName }
                        certFindings.append(certFinding)
                    else:
                        certName = subject_match
                        port = item.get('port')
                        certFinding = {"Host": name, "Port": port, "Issue": "Certificate expired", "Reason": certExpiry, "Certificate Name": certName }
                        certFindings.append(certFinding)
    return certFindings


def exportCertIssues2Csv(args, certFindings):
    filename = '{}_{}.csv'.format("UntrustedCerts", args.n)
    with open(filename, 'w', newline='') as f: #Create Csv file
        fieldNames = ['Host', 'Port', 'Issue', 'Reason', 'Certificate Name'] # Csv headers
        writer = csv.DictWriter(f, fieldnames=fieldNames)        
        writer.writeheader()
        for i in certFindings:
            writer.writerow(i) # Write the findings to a row


if __name__ == "__main__":
    parser = cert2rArgumentParser()
    args = cert2rArgumentOptions(parser)
    if validateInput(parser, args) == "validated":
        print(colours.INFO + "[i] Finding All Untrusted Certificates" + colours.END)
        certFindings = untrustedCerts(args)
        print(colours.INFO + "[i] Exporting to CSV" + colours.END)
        exportCertIssues2Csv(args, certFindings)
        print(colours.INFO + "[i] Done!" + colours.END)







