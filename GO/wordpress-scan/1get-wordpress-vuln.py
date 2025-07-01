import requests
from bs4 import BeautifulSoup
import json
import re
import time
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Deshabilitar las advertencias de solicitudes HTTPS no verificadas
warnings.simplefilter("ignore", InsecureRequestWarning)

cookie='wordfence_cookie_consent=%7B%22analytical%22%3Atrue%2C%22targeting%22%3Atrue%7D; _gcl_au=1.1.1186997439.1751106189; _ga_6THBZHGE0J=GS2.1.s1751333586$o7$g0$t1751333586$j60$l0$h0; _ga=GA1.1.2137489218.1751106190; __hstc=151178726.3ce2cfaeaa6fa239a7a194d45f3b0801.1751106200601.1751303389097.1751333586769.7; hubspotutk=3ce2cfaeaa6fa239a7a194d45f3b0801; aws-waf-token=f842f9d3-cc18-4757-b6f6-11f6c431e618:EAoAgUt4ngcXAQAA:BlGmsW50ZB+nPyWI2s2j4vtTJIDpyl8VLbuhRrE3tARUfgDlF4Q3o+xeXIV0QtflswFvlGalele5Xx859sxlh2i1SMa/78iWtproTeWB+ZD1rwmTs7V+f1TPKUZ5a1lCp2LQTiPv/ISASROR05R+1G7HNBwMQvY6UK7eQd0K58EK+w+7vqCJHu1I8qaEOEwzQn5Q6BXR3vT9c8sxJppVqtlFPPmAD2hja3OPfZwGVKEtYgutFdzjQx2TCUewXDxKM+7J27k=; __hssc=151178726.1.1751333586769'
# Configuración del proxy
proxies = {
    'http': 'http://127.0.0.1:8081',
    'https': 'http://127.0.0.1:8081'
}



# Estructura de datos principal
data = []

# Lista de vulnerabilidades a buscar
vulnerabilities = [
    "SQL Injection",
    "Backup Download",
    "Remote Code Execution",    
    "Local File Inclusion",
    "Remote File Inclusion",
    "Arbitrary File Upload",
    "Authentication Bypass",
    "Directory Traversal",
    "Sensitive Information Exposure"
]

# Función para realizar solicitudes HTTP con manejo de errores y encabezados
def fetch_url(url, verify_ssl=False, custom_headers=None):
    try:
        # Usa los encabezados personalizados si se proporcionan
        response = requests.get(url, proxies=proxies, verify=verify_ssl, headers=custom_headers or headers)
        #response = requests.get(url, verify=verify_ssl, headers=custom_headers or headers)
        response.raise_for_status()  # Lanza una excepción si la respuesta no es 200
        return response
    except requests.exceptions.RequestException as e:
        print(f"    [!] Error al realizar la solicitud a {url}: {str(e)}")
        return None

for vulnerability in vulnerabilities:
    print(f"\n[+] Buscando vulnerabilidad: {vulnerability}")
    encoded_vulnerability = requests.utils.quote(vulnerability)
    
    for page in range(1, 60):
        print(f"\n  [+] Página {page}")
        url = f"https://www.wordfence.com/threat-intel/vulnerabilities/search?search={encoded_vulnerability}&cwe_type=-&cvss_rating=-&date_month=-&page={page}"
        
        # Encabezados personalizados
        headers = {
            "Cookie": f"{cookie}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Te": "trailers"
        }

        response = fetch_url(url,custom_headers=headers)
        status_code = response.status_code
        print(f'status_code {status_code}')
        if status_code == 202:
            cookie = input('token?')
            headers = {
            "Cookie": f"{cookie}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Te": "trailers"
            }
            response = fetch_url(url,custom_headers=headers)
            status_code = response.status_code
            print(f'new status_code {status_code}')


        html = response.text
        if not html:
            print("    [!] No se pudo obtener la página, pasando a la siguiente")
            break
            
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extraer enlaces de la tabla
        table = soup.find('table')
        if not table:
            print("    [!] No se encontró tabla, pasando a siguiente página")
            break
            
        links = [a['href'] for a in table.select('td a') if 'CVERecord' not in a['href'] and 'researcher' not in a['href']]
        
        if not links:
            print("    [!] No hay más enlaces, pasando a siguiente vulnerabilidad")
            break
            
        for link in links:
            print(f"\n    [+] Procesando: {link}")
            item_data = {"link-wordfence": link}
                        
            headers = {
            "Cookie": f"{cookie}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Te": "trailers"
            }

            excluded_roles = ['Contributor', 'Subscriber', 'admin', 'editor', 'Project Manager']
    
            # Skip link if it contains any excluded role
            if any(role in link for role in excluded_roles):
                print(f"    [!] Skipping link with excluded role: {link}")
                continue

            response = fetch_url(link, custom_headers=headers)
            html_detail = response.text
            status_code = response.status_code
            print(f'new status_code {status_code}')
            if status_code == 202:
                cookie = input('token?')
                headers = {
                "Cookie": f"{cookie}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Te": "trailers"
                }
                response = fetch_url(link,custom_headers=headers)
                status_code = response.status_code                
                print(f'new status_code {status_code}')

            html_detail = response.text
            if not html_detail:
                continue
                
            soup_detail = BeautifulSoup(html_detail, 'html.parser')
            
            # Extraer CVE
            cve_link = soup_detail.find('a', href=re.compile(r'CVERecord'))
            if cve_link:
                item_data["cve"] = cve_link.get_text(strip=True)
            
            # Extraer Software Slug
            try:
                software_slug = soup_detail.find('th', string='Software Slug').find_next_sibling('td').get_text(strip=True).split('\n')[0]
                item_data["Software-Slug"] = software_slug
            except AttributeError:
                pass
            
            # Extraer instalaciones activas
            try:
                wp_link = soup_detail.find('th', string='Software Slug').find_next_sibling('td').find('a')['href']
                item_data["wordpress-link"] = wp_link
                headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Te": "trailers"
                }
                response = fetch_url(wp_link, custom_headers=headers)
                html_wp = response.text
                if html_wp:
                    soup_wp = BeautifulSoup(html_wp, 'html.parser')
                    installs_text = soup_wp.find(text=re.compile(r'Active installations:'))
                    if installs_text:
                        installs = re.search(r'Active installations:.*?([\d,]+)\+?', str(installs_text.parent)).group(1)
                        item_data["active-installations"] = int(installs.replace(',', ''))
                        
            except Exception as e:
                print(f"      [!] Error obteniendo instalaciones: {str(e)}")
            
            data.append(item_data)
            print(f"      [✓] Datos guardados: {json.dumps(item_data, indent=2)}")
            
            # Guardar progreso después de cada item
            with open('vulnerabilidades-criticas.json', 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            time.sleep(1)  # Espera para evitar bloqueos

print("\n[+] Proceso completado. Datos guardados en vulnerabilidades-criticas.json")
