if __name__ == "__main__":
    import requests
    import os
    import re
    import sys
    import threading
    import json
    import time
    from bs4 import BeautifulSoup
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    
    starttime = time.time()

    robtexip = [] 
    robtexurl = [] 
    threatcrowd = [] 
    urlhaus = []
    lookup = [] 
    def reqs(argv):
        for a in argv: 
            url = 'https://urlhaus.abuse.ch/browse.php?search={}'.format(a)
            urlhaus.append(url) 
            url1 = 'https://www.threatcrowd.org/ip.php?ip={}'.format(a)
            threatcrowd.append(url1)    
            url2 = 'https://www.threatcrowd.org/domain.php?domain={}'.format(a) 
            threatcrowd.append(url2)    
            if re.match(r"[\d\.]+",a) is not None: #This regex searches for IP address format and will return the ip, if not it will go to the else statement on 21
                url = 'https://www.robtex.com/ip-lookup/{}'.format(a) #robtex url to search with the ip from self.ip in the url to search
                robtexip.append(url) #appends robtex url with ips to search to the urls list
            else:
                url = 'https://www.robtex.com/ip-lookup/{}'.format(a) #robtex url to search with the ip from self.ip in the url to search
                robtexurl.append(url) #appends robtex url with ips to search to the urls list     
    #reqs(sys.argv[1:])
    works = []
    inp = sys.argv[1:]
    req = threading.Thread(target=reqs,args=(inp[0:],))
    works.append(req)
    req.start()


    def robte(robtip,robturl):
        if robtip != None:
            response = requests.get(robtip, verify=False) #get request to completed robtex url from above
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
                lookup.append(robtip+' Nothing Found! Trying pinging the host and looking up that IP')
            
        if robturl != None:
            response = requests.get(robturl, verify=False) #get request to completed robtex url from above
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
                lookup.append(robturl+' Nothing Found! Trying pinging the host and looking up that IP')
            elif len(results2) > 8:
                lookup.append(results2[2]+' | '+results2[0]+results2[1]+' | '+results2[5]+' | '+results2[7]+' | '+results2[8]+' '+results2[9])
            else:
                lookup.append(results2[0]+results2[1])

    def threatcrow(ur):
        response = requests.get(ur, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser') 
        results = soup.find_all('a', class_='text-uppercase')  
        results1 = soup.find_all('table', class_='table table-striped')  
        results2 = re.findall(r"[\w\s\-\_\.\,\(\)\!\#\$\%\^\&\*\@\;\:]+(?=\<\/)", str(results), re.M|re.I) 
        results3 = re.findall(r"\/domain[\w\-\.\_\?\=]+(?=\")(?!\<)", str(results1), re.M|re.I) 
        ip = re.findall(r"[\w\-\_\.]+$", str(ur), re.M|re.I)
        for r3 in results3:
            lookup.append("https://www.threatcrowd.org" + '{}'.format(r3) + ' {}'.format(ip) )
        for r in results2:
            lookup.append("https://www.threatcrowd.org/malware.php?md5=" + '{}'.format(r) + ' {}'.format(ip) )

    """def urlhau(urlh):
        response = requests.get(urlh, verify=False) 
        soup = BeautifulSoup(response.text, 'html.parser') 
        results = re.findall(r"(?<=\>)http.*(?=\<\/a\>\<\/td\>\<td\>\<span class\=\"badge badge.*\"\>)", str(soup), re.M|re.I)
        lookup.append(results)"""




    def threads():
        
        jobs = []
        for robtip in robtexip:
            b = threading.Thread(target=robte, args=(robtip,None,))
            jobs.append(b)
            time.sleep(.22)
            b.start()
        for robturl in robtexurl:
            b1 = threading.Thread(target=robte, args=(None,robturl,))
            jobs.append(b1)
            time.sleep(.22)
            b1.start()
        for ur in threatcrowd:
            b2 = threading.Thread(target=threatcrow,args=(ur,))
            jobs.append(b2)
            time.sleep(.256)
            b2.start()
        """for urlh in urlhaus:
            b3 = threading.Thread(target=urlhau, args=(urlh,))
            jobs.append(b3)
            time.sleep(.1)
            b3.start()"""
        for j in jobs:
            j.join()

    threads()



    for l in lookup:
        print(l)


    endtime = time.time() - starttime
    print("This took "+  str(endtime) + " seconds")