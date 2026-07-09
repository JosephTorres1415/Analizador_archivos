"""
=====================================================================
 ANALIZADOR BÁSICO DE ARCHIVOS SOSPECHOSOS
=====================================================================
Proyecto de Ciberseguridad - Blog Personal

Este script analiza un archivo y genera:
  1) El hash SHA-256 (para verificar integridad / identificar el archivo)
  2) Una búsqueda de cadenas de texto sospechosas dentro del archivo
  3) Información básica del archivo (tamaño, extensión, fecha)
  4) Un nivel de riesgo simple (bajo / medio / alto) según lo encontrado
  5) Un reporte en HTML con diseño visual, fácil de mostrar o compartir

Solo usa librerías estándar de Python (no requiere instalar nada).

Autor: (Joseph Torres Condezo)
=====================================================================
"""

import hashlib
import os
import re
import string
from datetime import datetime


# ---------------------------------------------------------------
# 1) Lista de patrones/cadenas sospechosas
# ---------------------------------------------------------------
PALABRAS_SOSPECHOSAS = [
    "cmd.exe", "powershell", "-enc", "regsvr32", "rundll32",
    "wscript", "cscript", "certutil", "mshta", "invoke-expression",
    "downloadstring", "base64", "reverse shell", "netcat", "nc.exe",
]

# Patrones con expresiones regulares (URLs e IPs)
PATRON_URL = re.compile(r"https?://[^\s\"'<>]+")
PATRON_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def calcular_hash_sha256(ruta_archivo):
    """Calcula el hash SHA-256 de un archivo, leyéndolo por bloques."""
    sha256 = hashlib.sha256()
    with open(ruta_archivo, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            sha256.update(bloque)
    return sha256.hexdigest()


def extraer_cadenas_legibles(datos_binarios, longitud_minima=4):
    """
    Extrae cadenas de texto legibles (imprimibles) desde datos binarios.
    Es una versión simplificada del comando 'strings' de Linux.
    """
    cadenas = []
    actual = ""
    caracteres_validos = string.printable

    for byte in datos_binarios:
        caracter = chr(byte)
        if caracter in caracteres_validos and caracter not in "\x0b\x0c":
            actual += caracter
        else:
            if len(actual) >= longitud_minima:
                cadenas.append(actual)
            actual = ""
    if len(actual) >= longitud_minima:
        cadenas.append(actual)
    return cadenas


def buscar_indicadores_sospechosos(ruta_archivo):
    """
    Busca palabras clave sospechosas, URLs e IPs dentro del archivo.
    Devuelve un diccionario con los hallazgos.
    """
    with open(ruta_archivo, "rb") as f:
        datos = f.read()

    cadenas = extraer_cadenas_legibles(datos)
    texto_completo = "\n".join(cadenas)

    palabras_encontradas = []
    texto_minusculas = texto_completo.lower()
    for palabra in PALABRAS_SOSPECHOSAS:
        if palabra.lower() in texto_minusculas:
            palabras_encontradas.append(palabra)

    urls_encontradas = list(set(PATRON_URL.findall(texto_completo)))
    ips_encontradas = list(set(PATRON_IP.findall(texto_completo)))

    return {
        "palabras_clave": palabras_encontradas,
        "urls": urls_encontradas,
        "ips": ips_encontradas,
    }


def obtener_info_basica(ruta_archivo):
    """Obtiene información general del archivo: tamaño, extensión, fechas."""
    estadisticas = os.stat(ruta_archivo)
    nombre = os.path.basename(ruta_archivo)
    extension = os.path.splitext(nombre)[1] or "(sin extensión)"
    tamano_bytes = estadisticas.st_size

    if tamano_bytes < 1024:
        tamano_legible = f"{tamano_bytes} B"
    elif tamano_bytes < 1024 ** 2:
        tamano_legible = f"{tamano_bytes / 1024:.2f} KB"
    else:
        tamano_legible = f"{tamano_bytes / (1024 ** 2):.2f} MB"

    fecha_modificacion = datetime.fromtimestamp(
        estadisticas.st_mtime
    ).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "nombre": nombre,
        "extension": extension,
        "tamano": tamano_legible,
        "fecha_modificacion": fecha_modificacion,
    }


def calcular_nivel_riesgo(hallazgos):
    """
    Lógica simple para estimar un nivel de riesgo según la cantidad
    de indicadores sospechosos encontrados.
    """
    total_indicios = (
        len(hallazgos["palabras_clave"])
        + len(hallazgos["urls"])
        + len(hallazgos["ips"])
    )

    if total_indicios == 0:
        return "BAJO", "sin indicios sospechosos detectados"
    elif total_indicios <= 2:
        return "MEDIO", "se detectaron algunos indicios que ameritan revisión"
    else:
        return "ALTO", "se detectaron múltiples indicios sospechosos"


# ---------------------------------------------------------------
# Generación del reporte visual en HTML
# ---------------------------------------------------------------
COLORES_RIESGO = {
    "BAJO": {"color": "#2e7d32", "fondo": "#e8f5e9", "emoji": "✅"},
    "MEDIO": {"color": "#e65100", "fondo": "#fff3e0", "emoji": "⚠️"},
    "ALTO": {"color": "#c62828", "fondo": "#ffebee", "emoji": "🚨"},
}


def generar_lista_html(items, vacio_texto):
    if not items:
        return f'<p class="vacio">{vacio_texto}</p>'
    filas = "".join(f"<li><code>{item}</code></li>" for item in items)
    return f'<ul class="lista-hallazgos">{filas}</ul>'


def generar_reporte_html(ruta_archivo, info, hash_sha256, hallazgos, nivel, descripcion):
    estilo_riesgo = COLORES_RIESGO[nivel]

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Reporte de Análisis - {info['nombre']}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', Roboto, Arial, sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    margin: 0;
    padding: 40px 20px;
    color: #1a1a1a;
  }}
  .contenedor {{
    max-width: 780px;
    margin: 0 auto;
  }}
  .encabezado {{
    text-align: center;
    color: #f8fafc;
    margin-bottom: 28px;
  }}
  .encabezado h1 {{
    font-size: 26px;
    margin: 0 0 6px 0;
  }}
  .encabezado p {{
    color: #94a3b8;
    font-size: 14px;
    margin: 0;
  }}
  .tarjeta {{
    background: #ffffff;
    border-radius: 14px;
    padding: 24px 28px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
  }}
  .tarjeta h2 {{
    font-size: 15px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748b;
    margin: 0 0 14px 0;
    border-bottom: 2px solid #f1f5f9;
    padding-bottom: 10px;
  }}
  .fila-dato {{
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    font-size: 14px;
    border-bottom: 1px dashed #e2e8f0;
  }}
  .fila-dato:last-child {{ border-bottom: none; }}
  .fila-dato span:first-child {{ color: #64748b; }}
  .fila-dato span:last-child {{ font-weight: 600; text-align: right; }}
  .hash {{
    font-family: 'Courier New', monospace;
    font-size: 12.5px;
    background: #f1f5f9;
    padding: 10px 12px;
    border-radius: 8px;
    word-break: break-all;
    margin-top: 8px;
  }}
  .riesgo {{
    background: {estilo_riesgo['fondo']};
    border-radius: 14px;
    padding: 22px 28px;
    text-align: center;
    margin-bottom: 20px;
    border: 2px solid {estilo_riesgo['color']}33;
  }}
  .riesgo .nivel {{
    font-size: 30px;
    font-weight: 800;
    color: {estilo_riesgo['color']};
    letter-spacing: 0.04em;
  }}
  .riesgo .descripcion {{
    color: #475569;
    font-size: 14px;
    margin-top: 6px;
  }}
  .lista-hallazgos {{
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }}
  .lista-hallazgos li code {{
    background: #fef2f2;
    color: #b91c1c;
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 12.5px;
    display: inline-block;
  }}
  .vacio {{
    color: #94a3b8;
    font-size: 13.5px;
    font-style: italic;
    margin: 0;
  }}
  .pie {{
    text-align: center;
    color: #64748b;
    font-size: 12px;
    margin-top: 24px;
  }}
</style>
</head>
<body>
  <div class="contenedor">
    <div class="encabezado">
      <h1>🔍 Reporte de Análisis de Archivo</h1>
      <p>Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="riesgo">
      <div class="nivel">{estilo_riesgo['emoji']} RIESGO {nivel}</div>
      <div class="descripcion">{descripcion}</div>
    </div>

    <div class="tarjeta">
      <h2>Información del Archivo</h2>
      <div class="fila-dato"><span>Nombre</span><span>{info['nombre']}</span></div>
      <div class="fila-dato"><span>Extensión</span><span>{info['extension']}</span></div>
      <div class="fila-dato"><span>Tamaño</span><span>{info['tamano']}</span></div>
      <div class="fila-dato"><span>Última modificación</span><span>{info['fecha_modificacion']}</span></div>
    </div>

    <div class="tarjeta">
      <h2>Hash SHA-256 (huella digital del archivo)</h2>
      <div class="hash">{hash_sha256}</div>
    </div>

    <div class="tarjeta">
      <h2>Palabras clave sospechosas</h2>
      {generar_lista_html(hallazgos['palabras_clave'], "No se encontraron palabras clave sospechosas.")}
    </div>

    <div class="tarjeta">
      <h2>URLs encontradas</h2>
      {generar_lista_html(hallazgos['urls'], "No se encontraron URLs en el archivo.")}
    </div>

    <div class="tarjeta">
      <h2>Direcciones IP encontradas</h2>
      {generar_lista_html(hallazgos['ips'], "No se encontraron direcciones IP en el archivo.")}
    </div>

    <div class="pie">
      Proyecto de aprendizaje en Ciberseguridad · Análisis estático básico con Python
    </div>
  </div>
</body>
</html>
"""
    return html


# ---------------------------------------------------------------
# Salida en terminal 
# ---------------------------------------------------------------
def color_ansi(texto, codigo):
    return f"\033[{codigo}m{texto}\033[0m"


def imprimir_resumen_terminal(info, hash_sha256, hallazgos, nivel, descripcion):
    colores_nivel = {"BAJO": "92", "MEDIO": "93", "ALTO": "91"}
    print("\n" + "=" * 55)
    print(color_ansi(" ANALIZADOR DE ARCHIVOS SOSPECHOSOS ", "1;97;44"))
    print("=" * 55)
    print(f"Archivo:        {info['nombre']}")
    print(f"Tamaño:         {info['tamano']}")
    print(f"Modificado:     {info['fecha_modificacion']}")
    print(f"Hash SHA-256:   {hash_sha256}")
    print("-" * 55)
    print(f"Palabras clave sospechosas: {len(hallazgos['palabras_clave'])}")
    print(f"URLs encontradas:           {len(hallazgos['urls'])}")
    print(f"IPs encontradas:            {len(hallazgos['ips'])}")
    print("-" * 55)
    nivel_coloreado = color_ansi(f" RIESGO: {nivel} ", colores_nivel[nivel] + ";1")
    print(nivel_coloreado)
    print(descripcion)
    print("=" * 55 + "\n")


# ---------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------
def analizar_archivo(ruta_archivo, carpeta_salida="reportes"):
    if not os.path.isfile(ruta_archivo):
        print(f"❌ No se encontró el archivo: {ruta_archivo}")
        return

    info = obtener_info_basica(ruta_archivo)
    hash_sha256 = calcular_hash_sha256(ruta_archivo)
    hallazgos = buscar_indicadores_sospechosos(ruta_archivo)
    nivel, descripcion = calcular_nivel_riesgo(hallazgos)

    imprimir_resumen_terminal(info, hash_sha256, hallazgos, nivel, descripcion)

    os.makedirs(carpeta_salida, exist_ok=True)
    nombre_reporte = f"reporte_{os.path.splitext(info['nombre'])[0]}.html"
    ruta_reporte = os.path.join(carpeta_salida, nombre_reporte)

    html = generar_reporte_html(ruta_archivo, info, hash_sha256, hallazgos, nivel, descripcion)
    with open(ruta_reporte, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"📄 Reporte HTML generado en: {ruta_reporte}\n")
    return ruta_reporte


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python analizador_archivos.py <ruta_del_archivo>")
        print("Ejemplo: python analizador_archivos.py test_sample.txt")
    else:
        analizar_archivo(sys.argv[1])
