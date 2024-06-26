# Función que ordena una lista por longitud de las cadenas
def sort_by_length(input_list):
    return sorted(input_list, key=len)

# Leer nombres desde el archivo
with open('usuarios-es.txt', 'r') as file:
    names = file.readlines()

# Limpiar espacios y saltos de línea
names = [name.strip() for name in names]

# Ordenar nombres
sorted_names = sort_by_length(names)

# Imprimir nombres ordenados
for name in sorted_names:
    print(name)

# Opcional: guardar los nombres ordenados en un nuevo archivo
with open('nombres_ordenados.txt', 'w') as file:
    for name in sorted_names:
        file.write(name + '\n')

