import json

def combinar_vulnerabilidades(archivo_entrada, archivo_salida):
    try:
        with open(archivo_entrada, 'r', encoding='utf-8') as file:
            datos = json.load(file)

        # Crear un nuevo diccionario para almacenar los datos procesados
        datos_procesados = {}

        for entrada in datos:
            slug = entrada["Software-Slug"]
            if slug in datos_procesados:
                # Combina los CVE si el Software-Slug ya existe
                datos_procesados[slug]["cve"] += ", " + entrada["cve"]
            else:
                # Agrega la entrada al nuevo diccionario
                datos_procesados[slug] = entrada

        # Convertir el diccionario procesado de nuevo a una lista
        datos_finales = list(datos_procesados.values())

        # Escribir los datos procesados en el archivo de salida
        with open(archivo_salida, 'w', encoding='utf-8') as file:
            json.dump(datos_finales, file, indent=4)

        print("Archivo procesado con éxito. Datos guardados en:", archivo_salida)
    except Exception as e:
        print(f"Error al procesar el archivo: {e}")

# Reemplaza 'vulnerabilidades.json' con la ruta de tu archivo de entrada si es necesario
# y 'vulnerabilidades_procesadas.json' con el nombre del archivo de salida deseado
combinar_vulnerabilidades('vulnerabilidades-criticas.json', 'vulnerabilidades-criticas2.json')
