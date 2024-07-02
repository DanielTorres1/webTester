import json

# Ruta al archivo JSON
archivo_json = 'vulnerabilidades-criticas2.json'

# Leer y cargar los datos del archivo JSON
with open(archivo_json, 'r') as file:
    datos = json.load(file)

# Recorrer cada elemento en los datos
for elemento in datos:
    # Comprobar si "active-installations" es mayor que 10000
    #if elemento.get("active-installations", 0) > 10000:
    #print(elemento)
    link_wordfence = elemento["link-wordfence"]
    if 'wordpress-core' in link_wordfence:
        with open('core.txt', 'a') as file:
            file.write(f"link_wordfence: {link_wordfence}\n")
    else:
        try:
            software_slug = elemento["Software-Slug"]
            url_plugin = f"wp-content/plugins/{software_slug}/"
            cve = elemento["cve"]
            # Imprimir en el formato deseado
            print(f'{{"{software_slug}", "{url_plugin}","{cve}"}},')
        except:
            pass
        

