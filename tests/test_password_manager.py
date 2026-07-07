"""
test_password_manager.py
Tests unitarios para password_manager.py, usando pytest.

Corre con:
    pytest tests/ -v

Cada test usa una base de datos temporal (vía monkeypatch de DB_PATH)
para no tocar el vault.db real del usuario.
"""

import sys
from pathlib import Path

import pytest

# Permite importar password_manager.py desde la carpeta raíz del proyecto
sys.path.insert(0, str(Path(__file__).parent.parent))

import password_manager as pm


@pytest.fixture
def db_temporal(tmp_path, monkeypatch):
    """Redirige DB_PATH a un archivo temporal para no afectar vault.db real."""
    ruta_temporal = tmp_path / "vault_test.db"
    monkeypatch.setattr(pm, "DB_PATH", ruta_temporal)
    pm.inicializar_db()
    return ruta_temporal


# --------------------------------------------------------------------------
# Criptografía: derivación de llave y cifrado/descifrado
# --------------------------------------------------------------------------

def test_derivar_llave_es_determinista():
    """La misma contraseña + mismo salt siempre produce la misma llave."""
    salt = pm.generar_salt()
    llave1 = pm.derivar_llave("miContraseña123", salt)
    llave2 = pm.derivar_llave("miContraseña123", salt)
    assert llave1 == llave2
    assert len(llave1) == pm.KEY_SIZE


def test_derivar_llave_distinto_salt_da_distinta_llave():
    """El mismo password con salts distintos nunca debe dar la misma llave."""
    llave1 = pm.derivar_llave("miContraseña123", pm.generar_salt())
    llave2 = pm.derivar_llave("miContraseña123", pm.generar_salt())
    assert llave1 != llave2


def test_cifrar_descifrar_roundtrip():
    """Cifrar y luego descifrar debe devolver el texto original exacto."""
    salt = pm.generar_salt()
    llave = pm.derivar_llave("clave", salt)
    nonce, cifrado = pm.cifrar("Hola Mundo 123!", llave)
    resultado = pm.descifrar(nonce, cifrado, llave)
    assert resultado == "Hola Mundo 123!"


def test_descifrar_con_llave_incorrecta_falla():
    """AES-GCM debe rechazar el descifrado si la llave no es la correcta."""
    salt = pm.generar_salt()
    llave_correcta = pm.derivar_llave("clave_correcta", salt)
    llave_incorrecta = pm.derivar_llave("clave_incorrecta", salt)
    nonce, cifrado = pm.cifrar("dato secreto", llave_correcta)
    with pytest.raises(Exception):
        pm.descifrar(nonce, cifrado, llave_incorrecta)


def test_nonces_son_distintos_entre_cifrados():
    """Cada llamada a cifrar() debe generar un nonce distinto (nunca reusar)."""
    llave = pm.derivar_llave("clave", pm.generar_salt())
    _, nonce1 = pm.cifrar("mismo texto", llave)[0], pm.cifrar("mismo texto", llave)[0]
    nonce2 = pm.cifrar("mismo texto", llave)[0]
    nonce3 = pm.cifrar("mismo texto", llave)[0]
    assert nonce2 != nonce3


# --------------------------------------------------------------------------
# Generador de contraseñas y evaluación de fortaleza
# --------------------------------------------------------------------------

def test_generar_password_respeta_longitud():
    password = pm.generar_password_segura(longitud=20)
    assert len(password) == 20


def test_generar_password_incluye_todos_los_tipos_pedidos():
    password = pm.generar_password_segura(
        longitud=30, usar_mayus=True, usar_minus=True, usar_numeros=True, usar_simbolos=True
    )
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in pm.SIMBOLOS for c in password)


def test_generar_password_sin_simbolos():
    password = pm.generar_password_segura(longitud=20, usar_simbolos=False)
    assert not any(c in pm.SIMBOLOS for c in password)


def test_evaluar_fortaleza_password_debil():
    nivel, problemas = pm.evaluar_fortaleza("abc")
    assert nivel == "Débil"
    assert len(problemas) > 0


def test_evaluar_fortaleza_password_fuerte():
    nivel, problemas = pm.evaluar_fortaleza("Tr0ub4dor&3xtraLargo!")
    assert nivel == "Fuerte"
    assert problemas == []


# --------------------------------------------------------------------------
# Base de datos: CRUD de entradas
# --------------------------------------------------------------------------

def test_crear_y_listar_entrada(db_temporal):
    llave = pm.derivar_llave("clave", pm.generar_salt())
    nonce, cifrado = pm.cifrar("password123", llave)
    pm.crear_entrada("Gmail", "user@example.com", nonce, cifrado)

    entradas = pm.listar_entradas()
    assert len(entradas) == 1
    assert entradas[0][1] == "Gmail"
    assert entradas[0][2] == "user@example.com"


def test_obtener_entrada_y_descifrar(db_temporal):
    llave = pm.derivar_llave("clave", pm.generar_salt())
    nonce, cifrado = pm.cifrar("miPasswordSecreta", llave)
    pm.crear_entrada("GitHub", "dev@example.com", nonce, cifrado)

    id_creado = pm.listar_entradas()[0][0]
    _, _, nonce_guardado, cifrado_guardado = pm.obtener_entrada(id_creado)
    assert pm.descifrar(nonce_guardado, cifrado_guardado, llave) == "miPasswordSecreta"


def test_actualizar_entrada(db_temporal):
    llave = pm.derivar_llave("clave", pm.generar_salt())
    nonce, cifrado = pm.cifrar("passwordVieja", llave)
    pm.crear_entrada("Twitter", "user", nonce, cifrado)
    id_creado = pm.listar_entradas()[0][0]

    nuevo_nonce, nuevo_cifrado = pm.cifrar("passwordNueva", llave)
    pm.actualizar_entrada(id_creado, nuevo_nonce, nuevo_cifrado)

    _, _, n, c = pm.obtener_entrada(id_creado)
    assert pm.descifrar(n, c, llave) == "passwordNueva"


def test_eliminar_entrada(db_temporal):
    llave = pm.derivar_llave("clave", pm.generar_salt())
    nonce, cifrado = pm.cifrar("password", llave)
    pm.crear_entrada("Servicio", "user", nonce, cifrado)
    id_creado = pm.listar_entradas()[0][0]

    pm.eliminar_entrada(id_creado)
    assert pm.listar_entradas() == []


# --------------------------------------------------------------------------
# Cambio de contraseña maestra (re-cifrado completo)
# --------------------------------------------------------------------------

def test_cambiar_contrasena_maestra_preserva_datos(db_temporal, monkeypatch):
    salt = pm.generar_salt()
    llave_vieja = pm.derivar_llave("claveVieja123", salt)
    nonce_v, cifrado_v = pm.cifrar("VERIFICADOR_OK", llave_vieja)
    pm.guardar_config(salt, nonce_v, cifrado_v)

    nonce, cifrado = pm.cifrar("miPasswordGuardada", llave_vieja)
    pm.crear_entrada("Servicio", "user", nonce, cifrado)

    # Simulamos las dos entradas de pedir_password_oculta que pide la función
    respuestas = iter(["claveNuevaSegura456", "claveNuevaSegura456"])
    monkeypatch.setattr(pm, "pedir_password_oculta", lambda mensaje="": next(respuestas))

    llave_nueva = pm.cambiar_contrasena_maestra(llave_vieja)

    # La llave vieja ya no debe servir para el verificador
    salt_db, nonce_db, cifrado_db = pm.obtener_config()
    with pytest.raises(Exception):
        pm.descifrar(nonce_db, cifrado_db, llave_vieja)

    # La llave nueva sí debe descifrar el verificador y la entrada existente
    assert pm.descifrar(nonce_db, cifrado_db, llave_nueva) == "VERIFICADOR_OK"
    id_entrada = pm.listar_entradas()[0][0]
    _, _, n, c = pm.obtener_entrada(id_entrada)
    assert pm.descifrar(n, c, llave_nueva) == "miPasswordGuardada"


# --------------------------------------------------------------------------
# Backup: exportar / importar
# --------------------------------------------------------------------------

def test_exportar_e_importar_backup(db_temporal, tmp_path):
    salt = pm.generar_salt()
    llave = pm.derivar_llave("claveDeBackup", salt)
    nonce_v, cifrado_v = pm.cifrar("VERIFICADOR_OK", llave)
    pm.guardar_config(salt, nonce_v, cifrado_v)

    nonce, cifrado = pm.cifrar("passwordOriginal", llave)
    pm.crear_entrada("ServicioBackup", "user", nonce, cifrado)

    ruta_backup = tmp_path / "backup.json"
    pm.exportar_backup(str(ruta_backup))
    assert ruta_backup.exists()

    # Borramos todo y reimportamos
    conn = pm.conectar()
    conn.execute("DELETE FROM config")
    conn.execute("DELETE FROM entradas")
    conn.commit()
    conn.close()

    pm.importar_backup(str(ruta_backup))

    entradas = pm.listar_entradas()
    assert len(entradas) == 1

    salt_restaurado, nonce_r, cifrado_r = pm.obtener_config()
    llave_restaurada = pm.derivar_llave("claveDeBackup", salt_restaurado)
    assert pm.descifrar(nonce_r, cifrado_r, llave_restaurada) == "VERIFICADOR_OK"

    _, _, n, c = pm.obtener_entrada(entradas[0][0])
    assert pm.descifrar(n, c, llave_restaurada) == "passwordOriginal"
