# Reporter

<h2>
A tool to automate boring findings dicovered by Nessus (TLS and certificate issues) into a csv file format. 
This can be appeneded to a pentest report when there's a large amount of these issues.
</h1>

<h3>
Example usage:
</h3

```
usage: Reporter.py [-h] -i FILE [-n NAME] [-C] [-U] [-T] [-a]
```
```
This tool exports TLS 1.0, Untrusted Certificates and Weak TLS Cipher findings from a nessus file into a csv format.
Append this to your supporting material

optional arguments:
  -h, --help     show this help message and exit
  -i FILE        Nessus export file
  -n NAME        Output file name (<Finding>_Report_Tables)
  -C, --ciphers  Export weak ciphers to csv
  -U, --certs    Export untrusted certificates to csv
  -T, --tls1     Export TLS 1.0 to csv
  -a, --all      Export TLS 1.0, untrusted certs and weak ciphers to csv

```
