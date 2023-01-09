# vt-log-scanner
This python script uses the VirusTotal API to scan log files for indicators of compromise. It searches for irregularities and uses artifacts to flag potential threats.

## Prerequisites

* Python 3.6 or higher
* A VirusTotal API key. You can sign up for a free account at https://www.virustotal.com/gui/join-us

## Getting Started

1.  Clone or download this repository
2.  Navigate to the directory where you cloned or downloaded the repository
3.  Open vt-log-scanner.py in a text editor
4.  Replace (YOUR API KEY HERE) with your VirusTotal API key
5.  Run the script using python vt-log-scanner.py

## Input Files

* 'logs.txt': This is the log file that the script will scan. The script expects one log entry per line.
* 'top-100-domains.txt': This file contains the top 100 most popular domains. The script will use this file to exclude low risk traffic from the logs.

## Example Files

The repository includes an 'Example_files' directory with example input files. You can use these files to test the script.

## Contact

If you have any questions or issues with the script, please open an issue in this repository.
