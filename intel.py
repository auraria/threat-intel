import json
import re
import sys
import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


urlhaus = [] 
robtexip = [] 
robtexurl = [] 
threatcrowd = [] 
lookup = [] #list of lookup responses

class urlgrab:

    def __init__(self, argv): 

        self.ip = argv 
        for i in self.ip: 
            self.url = 'https://urlhaus.abuse.ch/browse.php?search={}'.format(i)
            urlhaus.append(self.url) 
            self.url1 = 'https://www.threatcrowd.org/ip.php?ip={}'.format(i)
            threatcrowd.append(self.url1)    
            self.url2 = 'https://www.threatcrowd.org/domain.php?domain={}'.format(i) 
            threatcrowd.append(self.url2)    
            if re.match(r"[\d\.]+",i) is not None: #This regex searches for IP address format and will return the ip, if not it will go to the else statement on 21
                self.url = 'https://www.robtex.com/ip-lookup/{}'.format(i) #robtex url to search with the ip from self.ip in the url to search
                robtexip.append(self.url) #appends robtex url with ips to search to the urls list
            else:
                self.url = 'https://www.robtex.com/ip-lookup/{}'.format(i) #robtex url to search with the ip from self.ip in the url to search
                robtexurl.append(self.url) #appends robtex url with ips to search to the urls list 
            


    def get(self):

        for i in robtexip: #loop to go through urls in the urls list
            response = requests.get(i, verify=False) #get request to completed robtex url from above
            soup = BeautifulSoup(response.text, 'html.parser')  #use Beautifulsoup's html parser for the output and assign that to soup
            results = soup.find_all('div', class_='dns')    #take html output from soup, find all div sets, under the class dns(this is all found from the html output itself)
            results2 = re.findall(r"(?<=\>)[\w\.\-\,\(\)\:\s\/]+(?!\<\/b)", str(results), re.M|re.I) #regex find all non-html data we want to view
            try:
                results2.remove('asname')
            except:
                pass
            try:
                results2.remove('a')
            except:
                pass
            try:
                results2.remove('ptr')
            except:
                pass
            try:
                results2.remove('bgp')
            except:
                pass
            try:
                results2.remove('descr')
            except:
                pass
            try:
                results2.remove('location')
            except:
                pass
            try:
                results2.remove('whois')
            except:
                pass
            try:
                results2.remove('route')
            except:
                pass
            try:
                results2.remove('rout')
            except:
                pass
            try:
                results2.remove('whoi')
            except:
                pass
            try:
                results2.remove('pt')
            except:
                pass
            try:
                results2.remove('asnam')
            except:
                pass
            try:
                results2.remove('desc')
            except:
                pass
            try:
                results2.remove('bg')
            except:
                pass
            try:
                results2.remove('locatio')
            except:
                pass
            if len(results2) >= 13:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[4]+' | '+results2[8]+' | '+results2[12])
            elif len(results2) == 12:
                lookup.append(results2[0]+' | '+results2[2]+' | '+results2[6]+' | '+results2[8]+' | '+results2[10]) 
            elif len(results2) == 11:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[6]+' | '+results2[8]+' | '+results2[10]) 
            elif len(results2) == 10:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[6]+' | '+results2[8])
            elif len(results2) == 9:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[6]+' | '+results2[8])
            elif len(results2) == 8:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[4]+' | '+results2[6])
            elif len(results2) == 7:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[4]+' | '+results2[6])
            elif len(results2) == 6:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[4])
            elif len(results2) == 5:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[4])
            elif len(results2) == 4:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2]+' | '+results2[3])
            elif len(results2) == 3:
                lookup.append(results2[0]+' | '+results2[1]+' | '+results2[2])
            elif len(results2) == 2:
                lookup.append(results2[0]+' | '+results2[1])
            elif len(results2) == 1:
                lookup.append(results2[0])
            elif len(results2) == 0:
                lookup.append(i+' Nothing Found! Trying pinging the host and looking up that IP')

        for u in robtexurl: #loop to go through urls in the urls list
            response = requests.get(u, verify=False) #get request to completed robtex url from above
            soup = BeautifulSoup(response.text, 'html.parser')  #use Beautifulsoup's html parser for the output and assign that to soup
            results = soup.find_all('div', class_='dns')    #take html output from soup, find all div sets, under the class dns(this is all found from the html output itself)
            results22 = re.findall(r"(?<=\>)[\w\.\-\,\(\)\:\d\s\/]+", str(results), re.M|re.I) #regex find all non-html data we want to view
            results2 = re.findall(r"[\w\.\-\,\:\s\.]{3,}",str(results22), re.I|re.M)
            try:
                results2.remove('asname')
            except:
                pass
            try:
                results2.remove('a')
            except:
                pass
            try:
                results2.remove('ptr')
            except:
                pass
            try:
                results2.remove('bgp')
            except:
                pass
            try:
                results2.remove('descr')
            except:
                pass
            try:
                results2.remove('location')
            except:
                pass
            try:
                results2.remove('whois')
            except:
                pass
            try:
                results2.remove('route')
            except:
                pass
            
            if len(results2) == 0:
                lookup.append(u+' Nothing Found! Trying pinging the host and looking up that IP')
            else:
                lookup.append(results2[0]+results2[1]+' | '+results2[2]+' | '+results2[5]+' | '+results2[7]+' | '+results2[8]+' '+results2[9])
        for u in urlhaus: 
            response = requests.get(u, verify=False) 
            soup = BeautifulSoup(response.text, 'html.parser') 
            results2 = re.findall(r"(?<=\>)http.*(?=\<\/a\>\<\/td\>\<td\>\<span class\=\"badge badge.*\"\>)", str(soup), re.M|re.I)
            lookup.append(results2)
        for u in threatcrowd:
            response = requests.get(u, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser') 
            results = soup.find_all('a', class_='text-uppercase')  
            results1 = soup.find_all('table', class_='table table-striped')  
            results2 = re.findall(r"[\w\s\-\_\.\,\(\)\!\#\$\%\^\&\*\@\;\:]+(?=\<\/)", str(results), re.M|re.I) 
            results3 = re.findall(r"\/domain[\w\-\.\_\?\=]+(?=\")(?!\<)", str(results1), re.M|re.I) 
            ip = re.findall(r"[\w\.]+$", str(u), re.M|re.I)
            for r3 in results3:
                lookup.append("https://www.threatcrowd.org" + '{}'.format(r3) + ' {}'.format(ip) )
            for r in results2:
                lookup.append("https://www.threatcrowd.org/malware.php?md5=" + '{}'.format(r) + ' {}'.format(ip) )


            

            
req = urlgrab(sys.argv[1:]) 
req.get() #runs get function with req assigned arg(s)

for l in lookup: #looping through the lookup array
    print(l) #print individual lookups
