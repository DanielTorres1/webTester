import urllib.request
from bs4 import BeautifulSoup
import json
import re

# Inicializamos el objeto JSON donde se almacenarán los datos
data = []

for i in range(42, 58):
    print(f"Visitando página número {i}...")
    url = f"https://www.wordfence.com/threat-intel/vulnerabilities/search?cwe_type=-&cvss_rating=critical&date_month=-&page={i}"
    response = urllib.request.urlopen(url)
    html = response.read()
    soup = BeautifulSoup(html, 'html.parser')

    # Extraemos los enlaces de la tabla
    table = soup.find('table')
    links = [a['href'] for a in table.select('td a')]

    for link in links:
        if 'CVERecord' not in link and 'researcher' not in link :
            print(f"Haciendo una petición GET a {link}...")
            response = urllib.request.urlopen(link)
            html = response.read()
            soup = BeautifulSoup(html, 'html.parser')

            item_data = {"link-wordfence": link}

            try:
                software_slug = soup.find('th', text='Software Slug').find_next_sibling('td').text.strip().split('\n')[0]                
                item_data["Software-Slug"] = software_slug
            except:
                pass

            try:
                wordpress_link = soup.find('th', text='Software Slug').find_next_sibling('td').find('a')['href']
                item_data["wordpress-link"] = wordpress_link

                print(f"Haciendo una petición GET a {wordpress_link}...")
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
