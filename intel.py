from bs4 import BeautifulSoup
import requests, json, re, sys, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


urlhaus = [] 
robtex = [] 
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
            self.url3 = 'https://www.robtex.com/ip-lookup/{}'.format(i)
            robtex.append(self.url3)   


    def get(self):

        for u in robtex:
            response = requests.get(u, verify=False) 
            soup = BeautifulSoup(response.text, 'html.parser')  
            results = soup.find_all('div', class_='dns')    
            results2 = re.findall(r"[\w\s\-\_\.\,\(\)\!\#\$\%\^\&\*\@\;\:]+(?=\<\/)", str(results), re.M|re.I) 
            if len(results2) > 40:
                lookup.append(results2[3]+' | '+results2[0]+results2[1]+' | '+results2[7]+' | '+results2[5]+' | '+results2[9]+' | '+results2[11])
            elif len(results2) >= 30:
                lookup.append(results2[3]+' | '+results2[0]+''+results2[1]+' | '+results2[5]+' | '+results2[9]+' | '+results2[13]+' | '+results2[15])
            #elif len(results2) <= 40:
            #    lookup.append(results2[0]+' | '+results2[2]+' | '+results2[6]+' | '+results2[8]+' | '+results2[10]+' | '+results2[12]) 
            elif len(results2) > 11:
                lookup.append(results2[0]+' | '+results2[2]+' | '+results2[6]+' | '+results2[8]+' | '+results2[10]+' | '+results2[11])
            elif len(results2) > 10:
                lookup.append(results2[0]+' | '+results2[2]+' | '+results2[6]+' | '+results2[8]+' | '+results2[10])
            elif len(results2) > 4:
                lookup.append(results2[0]+' | '+results2[2]+' | '+results2[4])
            elif len(results2) == 4:
                lookup.append(results2[0]+' | '+results2[2]+' | '+results2[3])
            elif len(results2) == 0:
                lookup.append(u+' Nothing Found! Trying pinging the host and looking up that IP')
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