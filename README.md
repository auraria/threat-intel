# threat-intel

Centralized threat intel script grabbing information from robtex, urlhaus, and threatcrowd.

# TODO:

 Adding additional threat feeds

# DONE:

Fixed Robtex Parsing issues(99%)

# Requirements:
Python3

# imports:
bs4, requests, json, re, sys, urllib3



# Usage:


python .\intel.py scarabstonemovingmethod.com

50.63.202.51 | scarabstonemovingmethod.com | 22 | GoDaddy.com, LLC (GODAD) | AS26496 | GODADDY GoDaddy.com, Inc.
['http://lucky.scarabstonemovingmethod[.]com/reload...', 'http://lucky.scarabstonemovingmethod[.]com/reload...']
https://www.threatcrowd.org/domain.php?domain=NS64.DOMAINCONTROL.COM ['scarabstonemovingmethod.com']

python .\intel.py 147.135.3.250

147.135.3.250 | OVH US LLC (OUL-16) | AS16276 | OVH  | PNAP-WDC002 Broadvoice WDC Routes | location
['http://147.135.3[.]250/bins/frosty.arm5', 'http://147.135.3[.]250/bins/frosty.arm7', 'http://147.135.3[.]250/bins/frosty.arm6', 'http://147.135.3[.]250/bins/frosty.m68k', 'http://147.135.3[.]250/bins/frosty.mips', 'http://147.135.3[.]250/bins/frosty.ppc', 'http://147.135.3[.]250/bins/frosty.arm', 'http://147.135.3[.]250/bins/frosty.sh4', 'http://147.135.3[.]250/bins/frosty.x86']
