#!/usr/bin/python3
# Ciphers2Report Debug Version

import re
import os, subprocess
import time
import xml.etree.ElementTree as ET
import sqlite3

from argparse import *

# Colours Class
class colours:
    HEADER = '\033[95m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    INFO = '\033[94m'
    PASS = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'


def displayBanner():
    banner = (colours.HEADER + """
    ____ _       _                   ____  ____                       _
    / ___(_)_ __ | |__   ___ _ __ ___|___ \|  _ \ ___ _ __   ___  _ __| |_
    | |   | | '_ \| '_ \ / _ \ '__/ __| __) | |_) / _ \ '_ \ / _ \| '__| __|
    | |___| | |_) | | | |  __/ |  \__ \/ __/|  _ <  __/ |_) | (_) | |  | |_
    \____|_| .__/|_| |_|\___|_|  |___/_____|_| \_\___| .__/ \___/|_|   \__|
            |_|                                       |_|
                                                                        2.0
    """ + colours.END)


# Argument Parser 
def c2rArgumentParser():
    __desc__="Nessus SSL/ TLS Parsing Tool - DEBUG\r\nThis tool is not at 100%, double check everything with Nessus."
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=__desc__
    )
    return parser


def c2rArgumentOptions(parser):
    # Argument Flags
    parser.add_argument('-i', metavar='FILE', help='Nessus export file', required=True)
    parser.add_argument('-n', metavar='NAME', default='Cipher', help='Name for output file names (default Cipher)')
    parser.add_argument('-c', '--csv', default=False, help='Export to CSV', action='store_true')
    parser.add_argument('-r', '--report', default=False, help='"Pretty" Table Print', action='store_true')

    args = parser.parse_args()
    return args


listRC4 = ["0xC0,0x11","0xC0,0x07","0x00,0x66","0xC0,0x16","0x00,0x18","0xC0,0x0C","0xC0,0x02","0x00,0x05","0x00,0x04","0x01,0x00,0x80","0x00,0x92","0x00,0x8A","0x00,0x20","0x00,0x24","0xC0,0x33","0x00,0x8E","0x08,0x00,0x80","0x00,0x65","0x00,0x64","0x00,0x60","0x00,0x17","0x00,0x03","0x02,0x00,0x80","0x00,0x28","0x00,0x2B"]
listNull = ["0xC0,0x10","0xC0,0x06","0xC0,0x15","0xC0,0x0B","0xC0,0x01","0xC0,0x3B","0xC0,0x3A","0xC0,0x39","0x00,0xB9","0x00,0xB8","0x00,0xB5","0x00,0xB4","0x00,0x2E","0x00,0x2D","0x00,0xB1","0x00,0xB0","0x00,0x2C","0x00,0x3B","0x00,0x02","0x00,0x01","0x00,0x00","0x00,0x00,0x00","0x00,0x82","0x00,0x83","0xFF,0x87","0xFF,0x80,0x10"]
listEXP = ["0x00,0x63","0x00,0x62","0x00,0x61","0x00,0x65","0x00,0x64","0x00,0x60","0x00,0x14","0x00,0x11","0x00,0x19","0x00,0x08","0x00,0x06","0x04,0x00,0x80","0x00,0x27","0x00,0x26","0x00,0x2A","0x00,0x29","0x00,0x0B","0x00,0x0E","0x00,0x17","0x00,0x03","0x02,0x00,0x80","0x00,0x28","0x00,0x2B","0x00,0x00,0x00"]
listANON = ["0xC0,0x19","0x00,0xA7","0x00,0x6D","0x00,0x3A","0x00,0xC5","0x00,0x89","0xC0,0x47","0xC0,0x5B","0xC0,0x85","0xC0,0x18","0x00,0xA6","0x00,0x6C","0x00,0x34","0x00,0xBF","0x00,0x9B","0x00,0x46","0xC0,0x46","0xC0,0x5A","0xC0,0x84","0xC0,0x16","0x00,0x18","0xC0,0x17","0x00,0x1B","0x00,0x1A","0x00,0x19","0x00,0x17","0xC0,0x15"]
listCBC = ["0xC0,0x28","0xC0,0x24","0xC0,0x14","0xC0,0x0A","0xC0,0x22","0xC0,0x21","0xC0,0x20","0x00,0xB7","0x00,0xB3","0x00,0x91","0xC0,0x9B","0xC0,0x99","0xC0,0x97","0x00,0xAF","0xC0,0x95","0x00,0x6B","0x00,0x6A","0x00,0x69","0x00,0x68","0x00,0x39","0x00,0x38","0x00,0x37","0x00,0x36","0xC0,0x77","0xC0,0x73","0x00,0xC4","0x00,0xC3","0x00,0xC2","0x00,0xC1","0x00,0x88","0x00,0x87","0x00,0x86","0x00,0x85","0xC0,0x19","0x00,0x6D","0x00,0x3A","0x00,0xC5","0x00,0x89","0xC0,0x2A","0xC0,0x26","0xC0,0x0F","0xC0,0x05","0xC0,0x79","0xC0,0x75","0x00,0x3D","0x00,0x35","0x00,0xC0","0xC0,0x38","0xC0,0x36","0x00,0x84","0x00,0x95","0x00,0x8D","0xC0,0x3D","0xC0,0x3F","0xC0,0x41","0xC0,0x43","0xC0,0x45","0xC0,0x47","0xC0,0x49","0xC0,0x4B","0xC0,0x4D","0xC0,0x4F","0xC0,0x65","0xC0,0x67","0xC0,0x69","0xC0,0x71","0xC0,0x27","0xC0,0x23","0xC0,0x13","0xC0,0x09","0xC0,0x1F","0xC0,0x1E","0xC0,0x1D","0x00,0x67","0x00,0x40","0x00,0x3F","0x00,0x3E","0x00,0x33","0x00,0x32","0x00,0x31","0x00,0x30","0xC0,0x76","0xC0,0x72","0x00,0xBE","0x00,0xBD","0x00,0xBC","0x00,0xBB","0x00,0x9A","0x00,0x99","0x00,0x98","0x00,0x97","0x00,0x45","0x00,0x44","0x00,0x43","0x00,0x42","0xC0,0x18","0x00,0x6C","0x00,0x34","0x00,0xBF","0x00,0x9B","0x00,0x46","0xC0,0x29","0xC0,0x25","0xC0,0x0E","0xC0,0x04","0xC0,0x78","0xC0,0x74","0x00,0x3C","0x00,0x2F","0x00,0xBA","0xC0,0x37","0xC0,0x35","0x00,0xB6","0x00,0xB2","0x00,0x90","0x00,0x96","0x00,0x41","0xC0,0x9A","0xC0,0x98","0xC0,0x96","0x00,0xAE","0xC0,0x94","0x00,0x07","0x05,0x00,0x80","0x03,0x00,0x80","0x00,0x94","0x00,0x8C","0x00,0x21","0x00,0x25","0xC0,0x3C","0xC0,0x3E","0xC0,0x40","0xC0,0x42","0xC0,0x44","0xC0,0x46","0xC0,0x48","0xC0,0x4A","0xC0,0x4C","0xC0,0x4E","0xC0,0x64","0xC0,0x66","0xC0,0x68","0xC0,0x70","0xC0,0x12","0xC0,0x08","0xC0,0x1C","0xC0,0x1B","0xC0,0x1A","0x00,0x16","0x00,0x13","0x00,0x10","0x00,0x0D","0xC0,0x17","0x00,0x1B","0xC0,0x0D","0xC0,0x03","0x00,0x0A","0x07,0x00,0xC0","0x07,0x01,0xC0","0x00,0x93","0x00,0x8B","0x00,0x1F","0x00,0x23","0xC0,0x34","0x00,0x8F","0xFE,0xFF","0xFF,0xE0","0x00,0x63","0x00,0x15","0x00,0x12","0x00,0x0F","0x00,0x0C","0x00,0x1A","0x00,0x62","0x00,0x09","0x06,0x00,0x40","0x06,0x01,0x40","0x00,0x1E","0x00,0x22","0xFE,0xFE","0xFF,0xE1","0x00,0x14","0x00,0x11","0x00,0x19","0x00,0x08","0x00,0x06","0x04,0x00,0x80","0x00,0x27","0x00,0x26","0x00,0x2A","0x00,0x29","0x00,0x0B","0x00,0x0E"]
listNoPFS = ["0x00,0xA5","0x00,0xA1","0x00,0x69","0x00,0x68","0x00,0x37","0x00,0x36","0x00,0xC2","0x00,0xC1","0x00,0x86","0x00,0x85","0x00,0xA7","0x00,0x6D","0x00,0x3A","0x00,0xC5","0x00,0x89","0xC0,0x3F","0xC0,0x41","0xC0,0x47","0xC0,0x55","0xC0,0x59","0xC0,0x5B","0xC0,0x7F","0xC0,0x83","0xC0,0x85","0x00,0xA4","0x00,0xA0","0x00,0x3F","0x00,0x3E","0x00,0x31","0x00,0x30","0x00,0xBC","0x00,0xBB","0x00,0x98","0x00,0x97","0x00,0x43","0x00,0x42","0x00,0xA6","0x00,0x6C","0x00,0x34","0x00,0xBF","0x00,0x9B","0x00,0x46","0xC0,0x3E","0xC0,0x40","0xC0,0x46","0xC0,0x54","0xC0,0x58","0xC0,0x5A","0xC0,0x7E","0xC0,0x82","0xC0,0x84","0x00,0x18","0x00,0x10","0x00,0x0D","0x00,0x1B","0x00,0x0F","0x00,0x0C","0x00,0x1A","0x00,0x19","0x00,0x0B","0x00,0x0E","0x00,0x17","0xC0,0x19","0xC0,0x32","0xC0,0x2E","0xC0,0x2A","0xC0,0x26","0xC0,0x0F","0xC0,0x05","0xC0,0x79","0xC0,0x75","0xC0,0x4B","0xC0,0x4F","0xC0,0x5F","0xC0,0x63","0xC0,0x89","0xC0,0x8D","0xC0,0x18","0xC0,0x31","0xC0,0x2D","0xC0,0x29","0xC0,0x25","0xC0,0x0E","0xC0,0x04","0xC0,0x78","0xC0,0x74","0xC0,0x4A","0xC0,0x4E","0xC0,0x5E","0xC0,0x62","0xC0,0x88","0xC0,0x8C","0xC0,0x16","0xC0,0x0C","0xC0,0x02","0xC0,0x17","0xC0,0x0D","0xC0,0x03","0xC0,0x15","0xC0,0x0B","0xC0,0x01"]
listFREAK = ["0x00,0x62","0x00,0x61","0x00,0x64","0x00,0x60","0x00,0x14","0x00,0x0E","0x00,0x08","0x00,0x06","0x04,0x00,0x80","0x00,0x03","0x02,0x00,0x80","0x00,0x00,0x00"]
#listSWEET32 = ["0x00,0x07","0x00,0x21","0x00,0x25","0xC0,0x12","0xC0,0x08","0xC0,0x1C","0xC0,0x1B","0xC0,0x1A","0x00,0x16","0x00,0x13","0x00,0x10","0x00,0x0D","0xC0,0x17","0x00,0x1B","0xC0,0x0D","0xC0,0x03","0x00,0x0A","0x00,0x93","0x00,0x8B","0x00,0x1F","0x00,0x23","0xC0,0x34","0x00,0x8F","0xFE,0xFF","0xFF,0xE0","0x00,0x63","0x00,0x15","0x00,0x12","0x00,0x0F","0x00,0x0C","0x00,0x1A","0x00,0x62","0x00,0x09","0x00,0x61","0x00,0x1E","0x00,0x22","0xFE,0xFE","0xFF,0xE1","0x00,0x14","0x00,0x11","0x00,0x19","0x00,0x08","0x00,0x06","0x00,0x27","0x00,0x26","0x00,0x2A","0x00,0x29","0x00,0x0B","0x00,0x0E"]
listSTRONG = ["0x00,0x9C","0x00,0x9D","0x00,0x9E","0x00,0x9F","0x00,0xA0","0x00,0xA1","0x00,0xA2","0x00,0xA3","0x00,0xA4","0x00,0xA5","0x00,0xA8","0x00,0xA9","0x00,0xAA","0x00,0xAB","0x00,0xAC","0x00,0xAD","0x13,0x01","0x13,0x02","0x13,0x03","0x13,0x04","0x13,0x05","0x16,0xB7","0x16,0xB8","0x16,0xB9","0x16,0xBA","0xC0,0x2B","0xC0,0x2C","0xC0,0x2D","0xC0,0x2E","0xC0,0x2F","0xC0,0x30","0xC0,0x31","0xC0,0x32","0xC0,0x50","0xC0,0x51","0xC0,0x52","0xC0,0x53","0xC0,0x54","0xC0,0x55","0xC0,0x56","0xC0,0x57","0xC0,0x58","0xC0,0x59","0xC0,0x5C","0xC0,0x5D","0xC0,0x5E","0xC0,0x5F","0xC0,0x60","0xC0,0x61","0xC0,0x62","0xC0,0x63","0xC0,0x6A","0xC0,0x6B","0xC0,0x6C","0xC0,0x6D","0xC0,0x6E","0xC0,0x6F","0xC0,0x7A","0xC0,0x7B","0xC0,0x7C","0xC0,0x7D","0xC0,0x7E","0xC0,0x7F","0xC0,0x80","0xC0,0x81","0xC0,0x82","0xC0,0x83","0xC0,0x86","0xC0,0x87","0xC0,0x88","0xC0,0x89","0xC0,0x8A","0xC0,0x8B","0xC0,0x8C","0xC0,0x8D","0xC0,0x8E","0xC0,0x8F","0xC0,0x90","0xC0,0x91","0xC0,0x92","0xC0,0x93","0xC0,0x9C","0xC0,0x9D","0xC0,0x9E","0xC0,0x9F","0xC0,0xA0","0xC0,0xA1","0xC0,0xA2","0xC0,0xA3","0xC0,0xA4","0xC0,0xA5","0xC0,0xA6","0xC0,0xA7","0xC0,0xA8","0xC0,0xA9","0xC0,0xAA","0xC0,0xAB","0xC0,0xAC","0xC0,0xAD","0xC0,0xAE","0xC0,0xAF","0xCC,0x13","0xCC,0x14","0xCC,0x15","0xCC,0xA8","0xCC,0xA9","0xCC,0xAA","0xCC,0xAB","0xCC,0xAC","0xCC,0xAD","0xCC,0xAE","0x00,0xFF"]
listSWEET32 = ["0xC0,0x12","0xC0,0x08","0xC0,0x1C","0xC0,0x1B","0xC0,0x1A","0x00,0x16","0x00,0x13","0x00,0x10","0x00,0x0D","0xC0,0x17","0x00,0x1B","0xC0,0x0D","0xC0,0x03","0x00,0x0A","0x00,0x93","0x00,0x8B","0x00,0x1F","0x00,0x23","0xC0,0x34","0x00,0x8F","0xFE,0xFF","0xFF,0xE0"]
possibleSWEET32 = ['0x00,0x07', '0x00,0x21', '0x00,0x25', '0x00,0x63', '0x00,0x15', '0x00,0x12', '0x00,0x0F', '0x00,0x0C', '0x00,0x1A', '0x00,0x62', '0x00,0x09', '0x00,0x61', '0x00,0x1E', '0x00,0x22', '0xFE,0xFE', '0xFF,0xE1', '0x00,0x14', '0x00,0x11', '0x00,0x19', '0x00,0x08', '0x00,0x06', '0x00,0x27', '0x00,0x26', '0x00,0x2A', '0x00,0x29', '0x00,0x0B', '0x00,0x0E']


#Is that file a Nessus File?
def validateInput(parser, args):
    if not os.path.isfile(args.i) or not args.i.endswith('.nessus'):
        parser.print_help()
        print(colours.FAIL + '\n[!] Nessus output file required' + colours.END)
        exit(1)
    else:
        return "validated"


# Intial checks to see what ciphers are on each host
def SupportedCiphers(args, c):
    root = ET.parse(args.i).getroot()
    report = root.find('Report')
    for host in report.findall('ReportHost'):
        name = host.get('name')
        for item in host.findall('ReportItem'):
            port = item.get('port')
            fname = item.find('fname').text
            if 'ssl_supported_ciphers' in fname and item.find('plugin_output') is not None:
                text = item.find('plugin_output').text
                for i in re.compile('^SSL Version : ', re.M).split(text):
                    cbcCiphers = rc4Ciphers = anonCiphers = expCiphers = nullCiphers = freakCiphers = noPFSCiphers = sweet32Ciphers = strongCiphers = ''
                    Exec = False
                    #i = re.sub(' +', ' ', i.strip())
                    match = re.search('(TLS|SSL)v\d{1,2}', i)
                    if match: # Fix Nessus' Protocol naming
                        protocol = match.group()
                        # The Longest of IF statements.
                        protocol = 'TLSv1.2' if protocol == "TLSv12" else "TLSv1.1" if protocol == "TLSv11" else "TLSv1.0" if protocol == "TLSv1" else "SSLv3.0" if protocol == "SSLv3" else "SSLV2.0" if protocol == "SSLv2" else "Unknown Protocol"

                    for j in re.compile('\n').split(i): # This iterates through every line in the block of text.
                        isCipher = False
                        strengthSearch = re.search('(.*?) Strength Ciphers', j) # Get the strength of the current Cipher we looking at
                        if strengthSearch:
                            strength = strengthSearch.group(1).lstrip()
                        match = re.search('^[\s]{2,}(.*?)[\s]{2,}([^\s]{1}x.{2}, [^\s]{1}x.{2}(, [^\s]{1}x.{2})?)[\s]{1,}(.*?)[\s]{2,}(.*?)[\s]{2,}(.*?)[\s]{2,}(.*?)', j) # This matches groups in Nessus new layout.
                        if match:
                            Exec= True
                            unknown = True
                            fullCode = '0x'
                            cipherString = match.group(1) # Nessus' name for ciphers
                            codeArray = match.group(2).strip(' ').split(',') # The Cipher Code
                            sslcode = match.group(2).replace(' ','')
                            encMethod = match.group(6)
                            if "GCM" in encMethod:
                                naming = cipherString.split("-")
                                newCiph = ''
                                for l in range (len(naming)-1):
                                    newCiph = newCiph + naming[l] + "-"
                                cipherString = newCiph + "GCM-" + naming[len(naming)-1]
                            if codeArray[0] == '0x00': codeArray.pop(0) # If the First Hex value of the Code is 0x00, Ditch it. BUT ONLY THE FIRST.
                            for i in codeArray:
                                fullCode += i.strip().replace('0x','')
                            encryption = match.group(6)

                            if sslcode in listRC4: unknown = False; rc4Ciphers += cipherString + "\n"
                            if sslcode in listCBC: unknown = False; cbcCiphers += cipherString + "\n"
                            if sslcode in listANON: unknown = False; anonCiphers += cipherString + "\n"
                            if sslcode in listEXP: unknown = False; expCiphers += cipherString + "\n"
                            if sslcode in listNull: unknown = False; nullCiphers += cipherString + "\n"
                            if sslcode in listFREAK: unknown = False; freakCiphers += cipherString + "\n"
                            if sslcode in listNoPFS: unknown = False; noPFSCiphers += cipherString + "\n"
                            if sslcode in listSWEET32: unknown = False; sweet32Ciphers += cipherString + "\n"
                            if sslcode in listSTRONG: unknown = False; strongCiphers += cipherString + "\n"
                            if sslcode in possibleSWEET32: print("[?] Possible SWEET32 Cipher: "+cipherString+"\n ???-- Double Check with Nessus, Please Inform Phil\n"); unknown = False

                            if unknown == True:
                                print("\n"+("#"*len(j))+"\nUnknown Cipher Detected! - Please Report this to Phil, he'll fix it... probably\n"+j+"\n"+("#"*len(j)))
                    if Exec == True:
                        rc4Ciphers.replace(" ", "").rstrip('\n')
                        cbcCiphers.replace(" ", "").rstrip('\n')
                        anonCiphers.replace(" ", "").rstrip('\n')
                        expCiphers.replace(" ", "").rstrip('\n')
                        nullCiphers.replace(" ", "").rstrip('\n')
                        freakCiphers.replace(" ", "").rstrip('\n')
                        noPFSCiphers.replace(" ", "").rstrip('\n')
                        sweet32Ciphers.replace(" ", "").rstrip('\n')
                        strongCiphers.replace(" ", "").rstrip('\n')
                        sql = ''' INSERT INTO ciphers(Host,Port,Protocol,Lucky13,RC4,Sweet32,FREAK,Anon,"NULL",Export,"No PFS",Secure)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?) '''
                        values = (name, port, protocol, cbcCiphers ,rc4Ciphers , sweet32Ciphers, freakCiphers, anonCiphers,nullCiphers,expCiphers,noPFSCiphers,strongCiphers)
                        c.execute(sql, values)
                        

def csvExport(dbName, args): # Pray you have sqlite3 installed, turn that DB into a CSV filel
    try:
        subprocess.Popen(["sqlite3 -header %s -separator , -csv \"select * from Ciphers;\" > Ciphers_%s.csv" %(dbName,args.n)], shell = True)
    except:
        print("Error when exporting to CSV, is sqlite3 installed?")


def exportCiphers2Csv(args):
        timestamp = time.strftime("%Y%m%dT%H%M%S") # UNIQUE DATE for filename
        filename = '{}-{}.db'.format(args.n, timestamp) # Filename...
        conn = sqlite3.connect(filename)# SQL stuff
        c = conn.cursor()
        c.execute('''CREATE TABLE ciphers
                (Host text, Port text, Protocol text, Lucky13 text, RC4 text, Sweet32 text, FREAK text, Anon text, "NULL" text, Export text, "No PFS" text, "Secure" text)''')
        print(colours.WARNING + "[i] This is a Debug Build! It will not find Logjam Ciphers, Double check all findings with Nessus!" + colours.END)
        print(colours.INFO + "[i] Finding All Supported Ciphers" + colours.END)
        SupportedCiphers(args, c)
        conn.commit()
        conn.close()
        print(colours.INFO + "[i] Exporting to CSV" + colours.END)
        csvExport(filename, args)
        print(colours.INFO + "[i] Done!" + colours.END)


if __name__ == "__main__": # The MAIN!
    parser = c2rArgumentParser()
    args = c2rArgumentOptions(parser)
    if validateInput(parser, args) == "validated":
        displayBanner()
        exportCiphers2Csv(args)

