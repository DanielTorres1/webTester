import urllib.request
import urllib.parse
from bs4 import BeautifulSoup
import json
import re
import time

# Inicializamos el objeto JSON donde se almacenarán los datos
data = []

# Create a list with the specified items
vulnerabilities = [
    "Unauthenticated Remote Code Execution",
    "Unauthenticated SQL Injection",
    "Unauthenticated Local File Inclusion",
    "Unauthenticated Remote File Inclusion",
    "Unauthenticated Arbitrary File Upload",
    "Authentication Bypass",
    "Directory Traversal",
    "Sensitive Information Exposure"
]

# Print each item in the list using a for loop
for vulnerability in vulnerabilities:
    print(f"vulnerability {vulnerability}")
    encoded_vulnerability = urllib.parse.quote(vulnerability)
    for i in range(1, 10): #max 10 pages
        print(f"Visitando página número {i}...")
        url = f"https://www.wordfence.com/threat-intel/vulnerabilities/search?search={encoded_vulnerability}&cwe_type=-&cvss_rating=-&date_month=-&page={i}"
        print (f'url {url}')
        response = urllib.request.urlopen(url)
        html = response.read()
        soup = BeautifulSoup(html, 'html.parser')

        # Extraemos los enlaces de la tabla
        table = soup.find('table')
        links = [a['href'] for a in table.select('td a')]
        if not links:  # Check if links list is empty
            print("No links found, quitting the loop.")
            break

        for link in links:
            if 'CVERecord' not in link and 'researcher' not in link : # si no es un enlace a CVE ni al autor
                print(f"\t [+] Haciendo una petición GET a {link}...")
                response = urllib.request.urlopen(link)
                html = response.read()
                soup = BeautifulSoup(html, 'html.parser')
                item_data = {"link-wordfence": link}

                try:
                    # Buscar el enlace que contiene el CVE
                    cve_link = soup.find('a', href=re.compile(r'https://www.cve.org/CVERecord\?id=CVE-\d{4}-\d+'))
                    
                    # Extraer el texto del enlace, que es el CVE
                    cve = cve_link.get_text() if cve_link else None
                    print(cve)
                    
                    item_data["cve"] = cve
                except:
                    pass

                try:
                    software_slug = soup.find('th', text='Software Slug').find_next_sibling('td').text.strip().split('\n')[0]                
                    item_data["Software-Slug"] = software_slug
                except:
                    pass

                try:
                    wordpress_link = soup.find('th', text='Software Slug').find_next_sibling('td').find('a')['href']
                    item_data["wordpress-link"] = wordpress_link

                    print(f"Haciendo una petición GET a {wordpress_link}...") # para buscar instalaciones activas
                    response = urllib.request.urlopen(wordpress_link)
                    html = response.read()
                    soup = BeautifulSoup(html, 'html.parser')

                    try:
                        active_installations = re.search(r'Active installations: <strong>(.*?)</strong>', str(soup)).group(1)
                        active_installations = active_installations.replace("+", "")  # Remover el '+'
                        active_installations = active_installations.replace(",", "")  # Remover las comas
                        active_installations_num = int(active_installations)  # Convertir a entero
                        item_data["active-installations"] = active_installations_num
                    except:
                        pass

                except:
                    pass

                data.append(item_data)
                print(data)
                print("\n")            
                with open('vulnerabilidades-criticas.json', mode='w', encoding='utf-8') as write_file: 
                    json.dump(data, write_file)


# Imprimimos el objeto JSON
#print(json.dumps(data, indent=4))
