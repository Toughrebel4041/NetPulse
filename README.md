# NetPulse
#### Written by: Toughrebel4041
```
##   ##  #######   # ##### ######   ##   ##  ####      #####   #######
###  ##   ##   #  ## ## ##  ##  ##  ##   ##   ##      ##   ##   ##   #
#### ##   ##         ##     ##  ##  ##   ##   ##      ##        ##
#######   ####       ##     #####   ##   ##   ##       #####    ####
## ####   ##         ##     ##      ##   ##   ##           ##   ##
##  ###   ##   #     ##     ##      ##   ##   ##  ##  ##   ##   ##   #
##   ##  #######    ####   ####      #####   #######   #####   #######
```

NetPulse is a basic comprehensive network scanner. It combines multiple features such as host discovery, port scanning, service detection, vulnerability detection, OS detection, banner grabbing, and logging into a single, easy-to-use tool.

```
Note: Both versions of NetPulse are still under development. The first version (NetPulse.py) only able to use some of its features, and the second version- I don't even know if it's working or just throw some random gibberish). I will finish this project asap.
```
## Features
- Host Discovery: Identifies live hosts in a given IP range.
- Port Scanning: Scans specified ports on each discovered host to find open ports.
- Service Detection: Identifies the service running on each open port.
- Vulnerability Detection: Checks identified services against a predefined list of known vulnerabilities.
- OS Detection: Guesses the operating system based on Nmap’s OS detection feature.
- Banner Grabbing: Retrieves the banner of the service running on each open port.
- Logging: Logs all results to netpulse.log.

## Requirements
- Python 3.x
- scapy
- nmap
- logging
These dependencies are listed in the requirements.txt file

1. To install the required libraries, run:
```bash
pip install scapy python-nmap
```

2. Usage
```bash
git clone https://github.com/Toughrebel4041/NetPulse
cd NetPulse
```
3. Run the Tool
```bash
python NetPulse.py
Enter the IP range to scan: 
For example: 192.168.1.0/24
```

4. View the Results
Results will be displayed on the terminal and logged to netpulse.log.

## Disclaimer
Please use this tool responsibly. Web scraping may be against the terms of service of some websites. Always ensure you have permission to scrape a website before doing so.

## This project is for educational purposes only.
