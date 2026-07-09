# Documentación del Proyecto

## Analizador Básico de Archivos Sospechosos

Este es un proyecto que hice mientras estaba aprendiendo sobre Ciberseguridad. La idea era juntar varios temas que estoy estudiando (programación en Python, conceptos básicos de ciberseguridad y un poco de desarrollo web) en un solo proyecto pequeño y sencillo.

## ¿Qué hace?

Es un script en Python que analiza un archivo y busca cosas que podrían ser sospechosas, como:

- Palabras relacionadas a comandos o scripts maliciosos (por ejemplo `powershell`, `cmd.exe`).
- URLs dentro del archivo.
- Direcciones IP dentro del archivo.

Con esa información, calcula el hash SHA-256 del archivo (una especie de "huella digital" única) y genera un reporte en HTML bonito y fácil de leer, con un color según qué tan sospechoso parece el archivo (verde = bajo riesgo, naranja = riesgo medio, rojo = riesgo alto).

## ¿Por qué lo hice?

Estoy aprendiendo ciberseguridad y quería practicar con algo real, aunque sea básico. Este proyecto me ayudó a entender conceptos como:

- Qué es un hash y para qué sirve.
- Qué son los indicadores de compromiso (cosas que pueden indicar que un archivo es malicioso).
- Cómo se ve un primer paso de "análisis estático" de un archivo (analizarlo sin ejecutarlo).

## ¿Qué NO hace?

Es importante ser honesto sobre esto: este proyecto **no es un antivirus** ni reemplaza herramientas profesionales. No ejecuta el archivo (por eso es seguro de usar), solo lo lee y busca patrones de texto. Es una herramienta educativa, pensada para aprender, no para uso profesional.

## Tecnologías usadas

- **Python** (librerías estándar: `hashlib`, `os`, `re`, `string`, `datetime` — no se necesita instalar nada extra).
- **HTML y CSS** para el reporte visual.

## Estructura del proyecto

```
analizador-archivos-sospechosos/
├── analizador_archivos.py     # el script principal
├── README.md                  # este archivo
├── MANUAL_TECNICO.md          # instrucciones de instalación y uso
└── reportes/                  # aquí se guardan los reportes generados (se crea solo)
```

## Ejemplo de resultado

Cuando corres el script sobre un archivo, obtienes algo así en la terminal:

```
=======================================================
 ANALIZADOR DE ARCHIVOS SOSPECHOSOS 
=======================================================
Archivo:        sospechoso.txt
Tamaño:         104 B
Hash SHA-256:   ee33efd629b1e461a28c14d57ef73f9ff3cac7e74fa45c...
-------------------------------------------------------
Palabras clave sospechosas: 3
URLs encontradas:           1
IPs encontradas:            1
-------------------------------------------------------
 RIESGO: ALTO 
=======================================================
```

Y además se genera un reporte HTML con el mismo resultado, pero con un diseño visual (tarjetas, colores, etc.) para que sea más fácil de entender y compartir.

## Próximos pasos (ideas para el futuro)

- [ ] Poder analizar todos los archivos de una carpeta de una vez.
- [ ] Agregar un modelo básico de Machine Learning en vez de solo contar palabras clave.
- [ ] Conectarlo con la API de VirusTotal para comparar el hash con una base de datos real.

## Créditos

Proyecto hecho como parte de mi proceso de aprendizaje, documentado en mi blog personal de tecnología, programación, ciberseguridad e inteligencia artificial.
