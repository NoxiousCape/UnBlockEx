# 🔓 UnBlockEx

> **Excel Password Removal Tool** — Descifra y desbloquea archivos Excel protegidos con contraseña mediante múltiples estrategias de ataque.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange)

---

## 📋 Descripción

UnBlockEx es una herramienta de escritorio con interfaz gráfica (GUI) desarrollada en Python que permite recuperar el acceso a archivos Excel (`.xlsx`, `.xlsm`, `.xls`, `.xlsb`) protegidos con contraseña, sin necesidad de software de pago.

Admite tres estrategias de ataque:

| Estrategia | Descripción |
|---|---|
| 🔑 **Contraseña conocida** | Descifra el archivo directamente si conoces o recuerdas la contraseña |
| 📖 **Ataque de diccionario** | Prueba contraseñas desde un archivo wordlist o pistas escritas manualmente |
| ⚡ **Fuerza bruta** | Genera y prueba todas las combinaciones posibles con charset y longitud configurables |

> ⚠️ **Uso ético:** Esta herramienta está destinada únicamente para recuperar archivos propios o con permiso explícito del propietario. El uso no autorizado puede ser ilegal.

---

## 🖥️ Captura de pantalla

![UnBlockEx UI](./assets/screenshot.png)

---

## 🚀 Instalación

### Requisitos

- Python 3.10 o superior
- pip

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/UnBlockEx.git
cd UnBlockEx
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Ejecutar la aplicación

```bash
python unblockex.py
```

---

## 📦 Dependencias

| Paquete | Versión | Propósito |
|---|---|---|
| `msoffcrypto-tool` | ≥6.0.0 | Descifrado de archivos Office cifrados |
| `tqdm` | ≥4.0.0 | Barras de progreso en CLI (soporte interno) |

Instalar manualmente:

```bash
pip install msoffcrypto-tool tqdm
```

---

## 🎮 Uso

### Interfaz Gráfica

Al ejecutar `unblockex.py`, se abre la ventana principal con tres pestañas:

#### 🔑 Known Password (Contraseña conocida)
1. Selecciona el archivo Excel con el botón **Browse**
2. Escribe la contraseña en el campo
3. Haz clic en **🔓 Decrypt & Save**
4. El archivo descifrado se guarda como `<nombre>_UNLOCKED.<ext>` en la misma carpeta

#### 📖 Dictionary Attack (Ataque de diccionario)
1. (Opcional) Selecciona un archivo `.txt` con contraseñas, una por línea
2. Escribe pistas personalizadas directamente en el cuadro de texto
3. Haz clic en **▶ Start Dictionary Attack**

#### ⚡ Brute Force (Fuerza bruta)
1. Selecciona el conjunto de caracteres (dígitos, letras, alfanumérico, personalizado)
2. Configura la longitud mínima y máxima
3. Revisa el estimado de combinaciones antes de iniciar
4. Haz clic en **▶ Start Brute Force**

> 💡 **Consejo:** Para fuerza bruta con solo dígitos y hasta 6 caracteres (~1M intentos) el proceso es rápido. Contraseñas alfanuméricas largas pueden tardar horas o días.

---

## 🗂️ Estructura del proyecto

```
UnBlockEx/
├── unblockex.py        # Aplicación principal (GUI + lógica)
├── requirements.txt    # Dependencias del proyecto
├── README.md           # Este archivo
├── .gitignore          # Archivos excluidos del repositorio
└── assets/             # Recursos (capturas de pantalla, íconos)
```

---

## ⚙️ Tipos de protección soportados

| Tipo | Soportado | Notas |
|---|---|---|
| Cifrado a nivel de archivo (AES-256) | ✅ | Requiere conocer o descubrir la contraseña |
| Protección de hoja (Sheet Protection) | 🔧 | Derivado: edita el XML dentro del ZIP |
| Protección de libro (Workbook Protection) | 🔧 | Similar a sheet protection |

---

## 📄 Licencia

Distribuido bajo la licencia **MIT**. Consulta el archivo `LICENSE` para más información.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor abre un *issue* o un *pull request* con tus propuestas.

---

*Desarrollado con ❤️ y Python*
