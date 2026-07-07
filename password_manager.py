"""
password_manager.py
Gestor de Contraseñas - Proyecto de portafolio de ciberseguridad.

Combina:
- hashlib (PBKDF2-HMAC-SHA256) para derivar una llave segura a partir
  de la contraseña maestra.
- cryptography (AES-256-GCM) para cifrar/descifrar cada contraseña
  guardada, con autenticación integrada (detecta manipulación de datos).
- sqlite3 para persistir la bóveda cifrada localmente.

Flujo:
1. Primera vez: se crea una contraseña maestra. Se deriva una llave con
   PBKDF2 y se guarda un "verificador" cifrado (NUNCA la contraseña en
   texto plano ni la llave).
2. Cada inicio: se pide la contraseña maestra, se deriva la llave otra
   vez con el mismo salt, y se intenta descifrar el verificador. Si
   funciona, la contraseña es correcta.
3. Con la llave en memoria (solo durante la sesión), se pueden crear,
   ver, editar y borrar entradas de servicio/usuario/password, cada una
   cifrada con AES-256-GCM.
"""

import os
import sys
import time
import json
import base64
import string
import secrets
import hashlib
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# Entrada de contraseña con asteriscos (en vez de pantalla en blanco)
# --------------------------------------------------------------------------

if sys.platform == "win32":
    import msvcrt

    def pedir_password_oculta(mensaje: str = "Contraseña: ") -> str:
        """
        Pide una contraseña mostrando un asterisco (*) por cada caracter
        escrito, en vez de dejar la pantalla en blanco. Soporta backspace.
        Funciona en Windows (usa msvcrt, incluido en Python por defecto).
        """
        print(mensaje, end="", flush=True)
        password = []
        while True:
            char = msvcrt.getch()
            if char in (b"\r", b"\n"):
                print()
                break
            elif char == b"\x08":  # tecla backspace
                if password:
                    password.pop()
                    print("\b \b", end="", flush=True)
            elif char == b"\x03":  # Ctrl+C
                raise KeyboardInterrupt
            else:
                try:
                    decoded = char.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                password.append(decoded)
                print("*", end="", flush=True)
        return "".join(password)

else:
    import getpass as _getpass_module

    def pedir_password_oculta(mensaje: str = "Contraseña: ") -> str:
        """
        En Mac/Linux se usa el getpass estándar (oculta la entrada sin
        mostrar asteriscos; es el comportamiento normal de esos sistemas).
        """
        return _getpass_module.getpass(mensaje)

# --------------------------------------------------------------------------
# Configuración criptográfica
# --------------------------------------------------------------------------

SALT_SIZE = 16                  # bytes del salt (128 bits)
KEY_SIZE = 32                    # 256 bits, requerido por AES-256
PBKDF2_ITERATIONS = 480_000      # recomendación OWASP (2023+) para PBKDF2-HMAC-SHA256
NONCE_SIZE = 12                  # tamaño estándar de nonce para AES-GCM

# Cuando el programa corre normal (python password_manager.py), __file__
# apunta a la carpeta del script. Cuando corre empaquetado como .exe con
# PyInstaller, sys.frozen existe y hay que usar la carpeta del ejecutable
# en vez de una carpeta temporal que PyInstaller borra al cerrar.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

DB_PATH = BASE_DIR / "vault.db"
INACTIVIDAD_MAXIMA_SEGUNDOS = 120  # bloquea la sesión tras 2 min sin usar el menú


# --------------------------------------------------------------------------
# Criptografía: derivación de llave + cifrado/descifrado
# --------------------------------------------------------------------------

def generar_salt() -> bytes:
    """Genera un salt aleatorio criptográficamente seguro."""
    return os.urandom(SALT_SIZE)


def derivar_llave(password_maestra: str, salt: bytes) -> bytes:
    """
    Deriva una llave de 256 bits a partir de la contraseña maestra
    usando PBKDF2-HMAC-SHA256. El salt asegura que la misma contraseña
    nunca produzca la misma llave en dos instalaciones distintas.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password_maestra.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def cifrar(texto_plano: str, llave: bytes) -> tuple[bytes, bytes]:
    """
    Cifra un texto usando AES-256-GCM.
    Devuelve (nonce, texto_cifrado). El nonce debe guardarse junto con
    el texto cifrado (no es secreto, pero nunca debe reutilizarse con
    la misma llave).
    """
    aesgcm = AESGCM(llave)
    nonce = os.urandom(NONCE_SIZE)
    texto_cifrado = aesgcm.encrypt(nonce, texto_plano.encode("utf-8"), None)
    return nonce, texto_cifrado


def descifrar(nonce: bytes, texto_cifrado: bytes, llave: bytes) -> str:
    """
    Descifra un texto cifrado con AES-256-GCM.
    Lanza una excepción si la llave es incorrecta o si el dato fue
    manipulado (la autenticación de GCM falla).
    """
    aesgcm = AESGCM(llave)
    texto_plano = aesgcm.decrypt(nonce, texto_cifrado, None)
    return texto_plano.decode("utf-8")


# --------------------------------------------------------------------------
# Generador de contraseñas seguras + evaluación de fortaleza
# --------------------------------------------------------------------------

SIMBOLOS = "!@#$%^&*()-_=+[]{}"


def generar_password_segura(
    longitud: int = 16,
    usar_mayus: bool = True,
    usar_minus: bool = True,
    usar_numeros: bool = True,
    usar_simbolos: bool = True,
) -> str:
    """
    Genera una contraseña aleatoria usando el módulo `secrets`, que usa
    el generador de números aleatorios del sistema operativo pensado
    para criptografía (a diferencia de `random`, que NO es seguro para
    esto). Garantiza al menos un caracter de cada tipo seleccionado.
    """
    conjuntos = []
    if usar_mayus:
        conjuntos.append(string.ascii_uppercase)
    if usar_minus:
        conjuntos.append(string.ascii_lowercase)
    if usar_numeros:
        conjuntos.append(string.digits)
    if usar_simbolos:
        conjuntos.append(SIMBOLOS)

    if not conjuntos:
        raise ValueError("Debes seleccionar al menos un tipo de caracter.")

    todos = "".join(conjuntos)
    if longitud < len(conjuntos):
        longitud = len(conjuntos)

    # Aseguramos al menos un caracter de cada conjunto elegido
    password = [secrets.choice(conjunto) for conjunto in conjuntos]
    password += [secrets.choice(todos) for _ in range(longitud - len(password))]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def evaluar_fortaleza(password: str) -> tuple[str, list[str]]:
    """
    Evalúa qué tan fuerte es una contraseña. Devuelve un nivel
    ("Débil", "Aceptable", "Fuerte") y una lista de razones si le falta
    algo. No es un análisis criptográfico riguroso (como zxcvbn), pero
    cubre los criterios básicos: longitud y variedad de caracteres.
    """
    problemas = []
    if len(password) < 8:
        problemas.append("menos de 8 caracteres")
    if not any(c.isupper() for c in password):
        problemas.append("sin mayúsculas")
    if not any(c.islower() for c in password):
        problemas.append("sin minúsculas")
    if not any(c.isdigit() for c in password):
        problemas.append("sin números")
    if not any(c in string.punctuation for c in password):
        problemas.append("sin símbolos")

    if not problemas and len(password) >= 16:
        nivel = "Fuerte"
    elif len(problemas) <= 1 and len(password) >= 8:
        nivel = "Aceptable"
    else:
        nivel = "Débil"

    return nivel, problemas


# --------------------------------------------------------------------------
# Base de datos: SQLite
# --------------------------------------------------------------------------

def conectar():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def inicializar_db():
    conn = conectar()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verificador_nonce BLOB NOT NULL,
            verificador_cifrado BLOB NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS entradas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            servicio TEXT NOT NULL,
            usuario TEXT NOT NULL,
            nonce BLOB NOT NULL,
            password_cifrada BLOB NOT NULL,
            fecha_creacion TEXT DEFAULT CURRENT_TIMESTAMP,
            fecha_modificacion TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def existe_config() -> bool:
    conn = conectar()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM config")
    resultado = cur.fetchone()[0]
    conn.close()
    return resultado > 0


def guardar_config(salt: bytes, nonce: bytes, texto_cifrado: bytes):
    conn = conectar()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO config (id, salt, verificador_nonce, verificador_cifrado) VALUES (1, ?, ?, ?)",
        (salt, nonce, texto_cifrado),
    )
    conn.commit()
    conn.close()


def obtener_config():
    conn = conectar()
    cur = conn.cursor()
    cur.execute("SELECT salt, verificador_nonce, verificador_cifrado FROM config WHERE id = 1")
    fila = cur.fetchone()
    conn.close()
    return fila  # (salt, nonce, cifrado) o None


def actualizar_config(salt: bytes, nonce: bytes, texto_cifrado: bytes):
    conn = conectar()
    cur = conn.cursor()
    cur.execute(
        "UPDATE config SET salt = ?, verificador_nonce = ?, verificador_cifrado = ? WHERE id = 1",
        (salt, nonce, texto_cifrado),
    )
    conn.commit()
    conn.close()


def crear_entrada(servicio: str, usuario: str, nonce: bytes, password_cifrada: bytes):
    conn = conectar()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO entradas (servicio, usuario, nonce, password_cifrada) VALUES (?, ?, ?, ?)",
        (servicio, usuario, nonce, password_cifrada),
    )
    conn.commit()
    conn.close()


def listar_entradas():
    conn = conectar()
    cur = conn.cursor()
    cur.execute("SELECT id, servicio, usuario FROM entradas ORDER BY servicio")
    filas = cur.fetchall()
    conn.close()
    return filas


def obtener_entrada(entrada_id: int):
    conn = conectar()
    cur = conn.cursor()
    cur.execute(
        "SELECT servicio, usuario, nonce, password_cifrada FROM entradas WHERE id = ?",
        (entrada_id,),
    )
    fila = cur.fetchone()
    conn.close()
    return fila


def actualizar_entrada(entrada_id: int, nonce: bytes, password_cifrada: bytes):
    conn = conectar()
    cur = conn.cursor()
    cur.execute(
        """UPDATE entradas
           SET nonce = ?, password_cifrada = ?, fecha_modificacion = CURRENT_TIMESTAMP
           WHERE id = ?""",
        (nonce, password_cifrada, entrada_id),
    )
    conn.commit()
    conn.close()


def eliminar_entrada(entrada_id: int):
    conn = conectar()
    cur = conn.cursor()
    cur.execute("DELETE FROM entradas WHERE id = ?", (entrada_id,))
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Backup: exportar / importar la bóveda completa (sigue cifrada)
# --------------------------------------------------------------------------

def exportar_backup(ruta: str) -> None:
    """
    Exporta el verificador (salt + config) y todas las entradas a un
    archivo JSON. Los valores siguen cifrados con AES-256-GCM tal como
    están en la base de datos: el backup NUNCA contiene contraseñas en
    texto plano, solo se cambia el formato de almacenamiento (bytes ->
    base64 para que quepan en JSON).
    """
    config = obtener_config()
    if config is None:
        raise RuntimeError("No hay una bóveda configurada todavía.")
    salt, nonce_v, cifrado_v = config

    entradas_completas = []
    for id_, _servicio, _usuario in listar_entradas():
        servicio, usuario, nonce, cifrado = obtener_entrada(id_)
        entradas_completas.append({
            "servicio": servicio,
            "usuario": usuario,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "password_cifrada": base64.b64encode(cifrado).decode("ascii"),
        })

    backup = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "verificador_nonce": base64.b64encode(nonce_v).decode("ascii"),
        "verificador_cifrado": base64.b64encode(cifrado_v).decode("ascii"),
        "entradas": entradas_completas,
    }

    with open(ruta, "w", encoding="utf-8") as archivo:
        json.dump(backup, archivo, indent=2, ensure_ascii=False)


def importar_backup(ruta: str) -> None:
    """
    Reemplaza la bóveda actual (config + entradas) con el contenido de
    un backup exportado antes. Requiere la misma contraseña maestra que
    se usó al exportarlo, porque el salt viaja dentro del backup.
    """
    with open(ruta, "r", encoding="utf-8") as archivo:
        backup = json.load(archivo)

    salt = base64.b64decode(backup["salt"])
    nonce_v = base64.b64decode(backup["verificador_nonce"])
    cifrado_v = base64.b64decode(backup["verificador_cifrado"])

    conn = conectar()
    cur = conn.cursor()
    cur.execute("DELETE FROM config")
    cur.execute("DELETE FROM entradas")
    conn.commit()
    conn.close()

    guardar_config(salt, nonce_v, cifrado_v)
    for entrada in backup["entradas"]:
        crear_entrada(
            entrada["servicio"],
            entrada["usuario"],
            base64.b64decode(entrada["nonce"]),
            base64.b64decode(entrada["password_cifrada"]),
        )


# --------------------------------------------------------------------------
# CLI: login y menú
# --------------------------------------------------------------------------

def configurar_contrasena_maestra() -> bytes:
    print("\n=== Primera vez: crea tu contraseña maestra ===")
    while True:
        password = pedir_password_oculta("Nueva contraseña maestra: ")
        confirmacion = pedir_password_oculta("Confirma la contraseña maestra: ")
        if password == confirmacion and len(password) >= 8:
            break
        print("Las contraseñas no coinciden o son muy cortas (mínimo 8 caracteres).")

    salt = generar_salt()
    llave = derivar_llave(password, salt)
    nonce, cifrado = cifrar("VERIFICADOR_OK", llave)
    guardar_config(salt, nonce, cifrado)
    print("Contraseña maestra creada correctamente.\n")
    return llave


def iniciar_sesion() -> bytes:
    salt, nonce, cifrado = obtener_config()
    intentos = 3
    while intentos > 0:
        password = pedir_password_oculta("Contraseña maestra: ")
        llave = derivar_llave(password, salt)
        try:
            texto = descifrar(nonce, cifrado, llave)
            if texto == "VERIFICADOR_OK":
                print("Sesión iniciada correctamente.\n")
                return llave
        except Exception:
            pass
        intentos -= 1
        print(f"Contraseña incorrecta. Intentos restantes: {intentos}")
    print("Demasiados intentos fallidos. Cerrando programa.")
    raise SystemExit(1)


def cambiar_contrasena_maestra(llave_actual: bytes) -> bytes:
    """
    Cambia la contraseña maestra: descifra todas las entradas existentes
    con la llave actual, genera un nuevo salt, deriva una nueva llave a
    partir de la nueva contraseña, y vuelve a cifrar todo (verificador +
    cada entrada) con la nueva llave. Nunca se pierde el acceso a las
    credenciales guardadas mientras se conozca la contraseña actual.
    """
    print("\n=== Cambiar contraseña maestra ===")
    while True:
        nueva_password = pedir_password_oculta("Nueva contraseña maestra: ")
        confirmacion = pedir_password_oculta("Confirma la nueva contraseña maestra: ")
        if nueva_password == confirmacion and len(nueva_password) >= 8:
            break
        print("Las contraseñas no coinciden o son muy cortas (mínimo 8 caracteres).")

    # Descifrar todas las entradas existentes con la llave actual
    ids_y_passwords = []
    for id_, _servicio, _usuario in listar_entradas():
        _, _, nonce, cifrado = obtener_entrada(id_)
        password_plano = descifrar(nonce, cifrado, llave_actual)
        ids_y_passwords.append((id_, password_plano))

    # Generar nueva llave con nuevo salt
    nuevo_salt = generar_salt()
    nueva_llave = derivar_llave(nueva_password, nuevo_salt)

    # Re-cifrar el verificador con la nueva llave
    nonce_v, cifrado_v = cifrar("VERIFICADOR_OK", nueva_llave)
    actualizar_config(nuevo_salt, nonce_v, cifrado_v)

    # Re-cifrar cada entrada con la nueva llave
    for id_, password_plano in ids_y_passwords:
        nonce, cifrado = cifrar(password_plano, nueva_llave)
        actualizar_entrada(id_, nonce, cifrado)

    print("Contraseña maestra actualizada. Todas tus credenciales se re-cifraron.\n")
    return nueva_llave


def revisar_seguridad_de_entradas(llave: bytes) -> None:
    """
    Descifra todas las entradas guardadas (solo en memoria, nunca se
    imprime la contraseña completa salvo que el usuario ya la vea con
    la opción 3) y reporta cuáles son débiles y cuáles se repiten entre
    distintos servicios.
    """
    entradas = listar_entradas()
    if not entradas:
        print("No hay credenciales guardadas para revisar.\n")
        return

    reportes_debiles = []
    passwords_vistas = {}  # password_texto_plano -> lista de "servicio (usuario)"

    for id_, servicio, usuario in entradas:
        _, _, nonce, cifrado = obtener_entrada(id_)
        password = descifrar(nonce, cifrado, llave)
        nivel, problemas = evaluar_fortaleza(password)
        if nivel != "Fuerte":
            razon = ", ".join(problemas) if problemas else "longitud corta"
            reportes_debiles.append(f"  - {servicio} ({usuario}): {nivel} — {razon}")
        etiqueta = f"{servicio} ({usuario})"
        passwords_vistas.setdefault(password, []).append(etiqueta)

    reutilizadas = {pw: lugares for pw, lugares in passwords_vistas.items() if len(lugares) > 1}

    print("\n=== Revisión de seguridad ===")
    if reportes_debiles:
        print(f"\nContraseñas débiles o aceptables ({len(reportes_debiles)}):")
        for linea in reportes_debiles:
            print(linea)
    else:
        print("\nNinguna contraseña débil detectada.")

    if reutilizadas:
        print(f"\nContraseñas reutilizadas en más de un servicio ({len(reutilizadas)}):")
        for lugares in reutilizadas.values():
            print(f"  - Usada en: {', '.join(lugares)}")
    else:
        print("\nNinguna contraseña reutilizada.")
    print()


def menu_principal(llave: bytes):
    ultima_actividad = time.time()
    while True:
        if time.time() - ultima_actividad > INACTIVIDAD_MAXIMA_SEGUNDOS:
            print(f"\nSesión bloqueada tras {INACTIVIDAD_MAXIMA_SEGUNDOS}s de inactividad.")
            print("Vuelve a ingresar tu contraseña maestra para continuar.\n")
            llave = iniciar_sesion()

        print("""
--- Gestor de Contraseñas ---
1. Agregar nueva credencial
2. Ver credenciales guardadas
3. Ver una contraseña específica
4. Editar una contraseña
5. Eliminar una credencial
6. Generar contraseña segura
7. Revisar contraseñas débiles o reutilizadas
8. Exportar backup cifrado
9. Importar backup cifrado
10. Cambiar contraseña maestra
11. Salir
""")
        opcion = input("Elige una opción: ").strip()
        ultima_actividad = time.time()

        if opcion == "1":
            agregar_credencial(llave)
        elif opcion == "2":
            ver_credenciales()
        elif opcion == "3":
            ver_password(llave)
        elif opcion == "4":
            editar_password(llave)
        elif opcion == "5":
            eliminar_credencial()
        elif opcion == "6":
            generar_contrasena_interactivo()
        elif opcion == "7":
            revisar_seguridad_de_entradas(llave)
        elif opcion == "8":
            exportar_backup_interactivo()
        elif opcion == "9":
            nueva_llave = importar_backup_interactivo()
            if nueva_llave is not None:
                llave = nueva_llave
        elif opcion == "10":
            llave = cambiar_contrasena_maestra(llave)
        elif opcion == "11":
            print("Hasta luego.")
            break
        else:
            print("Opción inválida.")


def generar_contrasena_interactivo():
    print("\n=== Generador de contraseña segura ===")
    entrada_longitud = input("Longitud deseada (Enter para 16): ").strip()
    try:
        longitud = int(entrada_longitud) if entrada_longitud else 16
    except ValueError:
        longitud = 16
    usar_simbolos = input("¿Incluir símbolos? (si/no): ").strip().lower() != "no"

    password = generar_password_segura(longitud=longitud, usar_simbolos=usar_simbolos)
    nivel, _ = evaluar_fortaleza(password)
    print(f"\nContraseña generada: {password}")
    print(f"Fortaleza: {nivel}\n")


def exportar_backup_interactivo():
    print("\n=== Exportar backup cifrado ===")
    ruta = input("Nombre del archivo (Enter para 'backup.json'): ").strip() or "backup.json"
    try:
        exportar_backup(ruta)
        print(f"Backup exportado a '{ruta}'. Sigue cifrado con tu contraseña maestra actual.\n")
    except Exception as error:
        print(f"No se pudo exportar el backup: {error}\n")


def importar_backup_interactivo():
    print("\n=== Importar backup cifrado ===")
    ruta = input("Ruta del archivo de backup a importar: ").strip()
    if not Path(ruta).exists():
        print("No se encontró ese archivo.\n")
        return None
    confirmar = input(
        "Esto REEMPLAZA toda tu bóveda actual con el contenido del backup. "
        "¿Continuar? (si/no): "
    ).strip().lower()
    if confirmar != "si":
        print("Importación cancelada.\n")
        return None

    importar_backup(ruta)
    print("Backup importado. Ingresa la contraseña maestra que usaste al exportarlo.\n")
    return iniciar_sesion()


def agregar_credencial(llave: bytes):
    servicio = input("Servicio (ej. Gmail, Facebook): ").strip()
    usuario = input("Usuario o correo: ").strip()

    generar = input("¿Generar una contraseña segura automáticamente? (si/no): ").strip().lower()
    if generar == "si":
        password = generar_password_segura()
        print(f"Contraseña generada: {password}")
    else:
        password = pedir_password_oculta("Contraseña a guardar: ")
        nivel, problemas = evaluar_fortaleza(password)
        if nivel != "Fuerte":
            razon = ", ".join(problemas) if problemas else "longitud corta"
            print(f"Aviso: fortaleza '{nivel}' ({razon}). Puedes guardarla igual si quieres.")

    nonce, cifrado = cifrar(password, llave)
    crear_entrada(servicio, usuario, nonce, cifrado)
    print("Credencial guardada.\n")


def ver_credenciales():
    entradas = listar_entradas()
    if not entradas:
        print("No hay credenciales guardadas.\n")
        return
    print("\nID | Servicio | Usuario")
    for id_, servicio, usuario in entradas:
        print(f"{id_} | {servicio} | {usuario}")
    print()


def ver_password(llave: bytes):
    ver_credenciales()
    try:
        entrada_id = int(input("ID de la credencial a ver: "))
    except ValueError:
        print("ID inválido.\n")
        return
    fila = obtener_entrada(entrada_id)
    if not fila:
        print("No se encontró esa credencial.\n")
        return
    servicio, usuario, nonce, cifrado = fila
    try:
        password = descifrar(nonce, cifrado, llave)
        print(f"\nServicio: {servicio}\nUsuario: {usuario}\nContraseña: {password}\n")
    except Exception:
        print("Error al descifrar (llave incorrecta o datos corruptos).\n")


def editar_password(llave: bytes):
    ver_credenciales()
    try:
        entrada_id = int(input("ID de la credencial a editar: "))
    except ValueError:
        print("ID inválido.\n")
        return
    nueva_password = pedir_password_oculta("Nueva contraseña: ")
    nonce, cifrado = cifrar(nueva_password, llave)
    actualizar_entrada(entrada_id, nonce, cifrado)
    print("Contraseña actualizada.\n")


def eliminar_credencial():
    ver_credenciales()
    try:
        entrada_id = int(input("ID de la credencial a eliminar: "))
    except ValueError:
        print("ID inválido.\n")
        return
    confirmar = input("¿Seguro que quieres eliminarla? (si/no): ").strip().lower()
    if confirmar == "si":
        eliminar_entrada(entrada_id)
        print("Credencial eliminada.\n")


def main():
    inicializar_db()
    if existe_config():
        llave = iniciar_sesion()
    else:
        llave = configurar_contrasena_maestra()
    menu_principal(llave)


if __name__ == "__main__":
    main()