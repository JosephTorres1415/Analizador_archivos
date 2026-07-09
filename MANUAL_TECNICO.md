# Manual Técnico

Guía de instalación y uso del **Analizador Básico de Archivos Sospechosos**.

## Requisitos

- Tener **Python 3.8 o más reciente** instalado.
- No necesitas instalar ninguna librería adicional, el script solo usa lo que ya viene con Python.
- Un navegador web para abrir el reporte (Chrome, Firefox, Edge, etc.).

Para revisar si tienes Python instalado, abre una terminal y escribe:

```bash
python3 --version
```

Si te muestra un número de versión (por ejemplo `Python 3.11.4`), ya estás listo.

## Instalación

1. Descarga o clona este repositorio.
2. Entra a la carpeta del proyecto:

```bash
cd analizador-archivos-sospechosos
```

Eso es todo, no hay que instalar nada más.

## Cómo usarlo

Ejecuta el script pasando como argumento la ruta del archivo que quieres analizar:

```bash
python3 analizador_archivos.py archivo_a_analizar.txt
```

Si el archivo está en otra carpeta, puedes usar la ruta completa:

```bash
python3 analizador_archivos.py /ruta/completa/al/archivo.exe
```

En Windows, si `python3` no funciona, prueba con `python`:

```bash
python analizador_archivos.py archivo_a_analizar.txt
```

## ¿Qué obtienes al ejecutarlo?

1. Un resumen en la terminal, con colores según el nivel de riesgo detectado.
2. Un reporte en HTML, guardado automáticamente en una carpeta llamada `reportes/`, con el nombre:

```
reportes/reporte_<nombre_del_archivo>.html
```

Solo ábrelo con doble clic y se verá en tu navegador.

## Cómo funciona por dentro (explicación simple)

El script sigue estos pasos, en orden:

1. **Lee el archivo** en modo binario (para poder leer cualquier tipo de archivo, no solo texto).
2. **Calcula el hash SHA-256**, que es como una huella digital única del archivo.
3. **Extrae el texto legible** que hay dentro del archivo (aunque el archivo no sea un `.txt`).
4. **Busca palabras sospechosas** en ese texto (por ejemplo `powershell`, `cmd.exe`, `-enc`), además de URLs e IPs usando expresiones regulares.
5. **Cuenta cuántas coincidencias encontró** y con eso decide un nivel de riesgo:

| Coincidencias encontradas | Nivel de riesgo |
|---|---|
| 0 | Bajo |
| 1 o 2 | Medio |
| 3 o más | Alto |

6. **Genera el reporte HTML** con toda esta información, usando colores distintos según el riesgo (verde, naranja o rojo).

## Funciones principales del código

Por si quieres entender o modificar el código, así está organizado:

| Función | Qué hace |
|---|---|
| `calcular_hash_sha256()` | Calcula el hash del archivo. |
| `extraer_cadenas_legibles()` | Saca el texto legible desde el archivo. |
| `buscar_indicadores_sospechosos()` | Busca palabras clave, URLs e IPs. |
| `obtener_info_basica()` | Obtiene nombre, tamaño, extensión y fecha del archivo. |
| `calcular_nivel_riesgo()` | Decide si el riesgo es bajo, medio o alto. |
| `generar_reporte_html()` | Crea el reporte visual en HTML. |
| `imprimir_resumen_terminal()` | Muestra el resumen en la terminal con colores. |
| `analizar_archivo()` | Función principal, junta todo el proceso. |

## Personalizar la lista de palabras sospechosas

Si quieres agregar o quitar palabras de la búsqueda, edita esta parte del código (`analizador_archivos.py`):

```python
PALABRAS_SOSPECHOSAS = [
    "cmd.exe", "powershell", "-enc", "regsvr32", "rundll32",
    "wscript", "cscript", "certutil", "mshta", "invoke-expression",
    "downloadstring", "base64", "reverse shell", "netcat", "nc.exe",
]
```

Solo agrega o elimina palabras de la lista, respetando las comillas y las comas.

## Problemas comunes

**"python3: command not found"**
→ Prueba con `python` en vez de `python3`, o instala Python desde [python.org](https://www.python.org/downloads/).

**El reporte no se abre bien / se ve sin estilos**
→ Asegúrate de abrir el archivo `.html` directamente con doble clic, no copiando el contenido a otro lugar.

**"No such file or directory"**
→ Verifica que estés escribiendo bien la ruta del archivo, o que la terminal esté ubicada en la carpeta correcta (usa `cd` para moverte).
