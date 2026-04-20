### Set Up

If you want to keep the packages segmented from your core system, create a python virtual environment:
`python -m venv .venv`
`source .venv/bin/activate`

Download the core package that enables packet capture scanning:
`pip install pyshark`

If you plan on using the scapy scripts to manually create packets:
`pip install scapy`

*Note: Pyshark does not work on some of the latest versions of python, so it might be necessary to downgrade to run. This can be done within the local python environment.*

### Script Use

`python allScan.py [packet capture file, .pcap, .cap, .capng]`
