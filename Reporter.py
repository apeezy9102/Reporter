import src.C2Rdebug as c2r
import src.CertIssues2Csv as cert2r
import src.TLS1Enabled as tls2r
import os


from argparse import *

# Colours for printing on terminal
class colours:
    HEADER = '\033[95m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    INFO = '\033[94m'
    PASS = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'


def reporterArgumentParser():
    # Tool description
    __desc__="This tool exports TLS 1.0, Untrusted Certificates and Weak TLS Cipher findings from a nessus file into a csv format.\r\nAppend this to your supporting material"

    # Argument Parser 
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=__desc__
    )
    return parser


# Argument Flags
def reporterArgumentOptions(parser):
    parser.add_argument('-i', metavar='FILE', help='Nessus export file', required=True)
    parser.add_argument('-n', metavar='NAME', default='Report_Tables', help='Output file name (<Finding>_Report_Tables)')
    parser.add_argument('-C', '--ciphers', default=False, help='Export weak ciphers to csv', action='store_true')
    parser.add_argument('-U', '--certs', default=False, help='Export untrusted certificates to csv', action='store_true')
    parser.add_argument('-T', '--tls1', default=False, help='Export TLS 1.0 to csv', action='store_true')
    parser.add_argument('-a', '--all', default=False, help='Export TLS 1.0, untrusted certs and weak ciphers to csv', action='store_true')

    args = parser.parse_args()
    return args


def validateInput(args, parser):
    if not os.path.isfile(args.i) or not args.i.endswith('.nessus'):
        parser.print_help()
        print(colours.FAIL + '\n[!] Nessus output file required' + colours.END)
        exit(1)    
    if args.ciphers == True:
        return "validated"
    elif args.certs == True:
        return "validated"
    elif args.tls1 == True:
        return "validated"
    elif args.all == True:
        return "validated"
    else:
        parser.print_help()
        print(colours.FAIL + '\n[!] Please select the findings you would like to export.\nFor example, to export all findings:\n\t"./Reporter.py -i File.nessus --all"\n' + colours.END)
        exit(1)    


def runCerts2Csv(reporter_args):
    print(colours.INFO + "[i] Finding All Untrusted Certificates" + colours.END)
    certFindings = cert2r.untrustedCerts(reporter_args)
    print(colours.INFO + "[i] Exporting to CSV" + colours.END)
    cert2r.exportCertIssues2Csv(reporter_args, certFindings)
    print(colours.INFO + "[i] Done!" + colours.END)


def runTLS2Csv(reporter_args):
    print(colours.INFO + "[i] Finding All TLS 1.0 Issues" + colours.END)
    tlsFindings = tls2r.tls1Supported(reporter_args)
    print(colours.INFO + "[i] Exporting to CSV" + colours.END)
    tls2r.exportTLS2Csv(reporter_args, tlsFindings)
    print(colours.INFO + "[i] Done!" + colours.END)


if __name__ == "__main__":
    parser = reporterArgumentParser()
    reporter_args = reporterArgumentOptions(parser)
    if validateInput(reporter_args, parser) == "validated":
        
        # Run TLS Ciphers 2 CSV
        if reporter_args.ciphers == True:
            c2r.exportCiphers2Csv(reporter_args)

        # Run Untrusted Certs 2 CSV
        if reporter_args.certs == True:
            runCerts2Csv(reporter_args)

        # Run TLS1 2 CSV
        if reporter_args.tls1 == True:
            runTLS2Csv(reporter_args)

        # Run All Findings 2 CSV
        if reporter_args.all == True:
            c2r.exportCiphers2Csv(reporter_args)
            runCerts2Csv(reporter_args)
            runTLS2Csv(reporter_args)
        
        



