# Gestor de Contraseñas

Gestor de contraseñas de línea de comandos escrito en Python. Deriva una
llave a partir de una contraseña maestra con **PBKDF2-HMAC-SHA256** y
usa esa llave para cifrar/descifrar cada credencial guardada con
**AES-256-GCM**, almacenando todo en una base de datos **SQLite** local.

Parte de un portafolio de ciberseguridad orientado a hacer estas
herramientas accesibles para comunidades hispanohablantes.

## Cómo funciona

1. **Primera vez**: se crea una contraseña maestra. Se genera un `salt`
   aleatorio y se deriva una llave de 256 bits con PBKDF2 (480,000
   iteraciones, recomendación OWASP). La contraseña maestra y la llave
   **nunca se guardan**; solo se guarda un "verificador" cifrado para
   confirmar la contraseña en futuros inicios.
2. **Cada inicio**: se pide la contraseña maestra, se deriva la llave
   otra vez con el mismo salt, y se intenta descifrar el verificador.
   Si el descifrado funciona, la contraseña es correcta.
3. **Uso**: con la llave en memoria (solo durante la sesión activa) se
   pueden crear, ver, editar y borrar credenciales, además de cambiar
   la contraseña maestra (re-cifrando todo automáticamente). Cada
   contraseña se cifra individualmente con un `nonce` distinto (AES-GCM
   nunca debe reusar un nonce con la misma llave).

## Estructura

```
password-manager/
├── password_manager.py   # Todo el programa: cripto, base de datos y CLI
├── requirements.txt
├── .gitignore
├── LICENSE
└── vault.db               # se crea automáticamente al correr el programa
                            # (no se sube a git)
```

## Instalación y uso

```bash
git clone https://github.com/AFBE10/password-manager.git
cd password-manager

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
python password_manager.py
```

La primera vez que lo corras te pedirá crear una contraseña maestra.
Cada persona que clone el repo genera su propia bóveda (`vault.db`)
vacía y local — nadie hereda credenciales de otra instalación.

## Decisiones de seguridad

- **PBKDF2-HMAC-SHA256, 480,000 iteraciones**: derivación de llave lenta
  a propósito para dificultar ataques de fuerza bruta offline.
- **Salt único por instalación**: evita ataques con tablas
  precalculadas (rainbow tables).
- **AES-256-GCM**: cifrado autenticado; si alguien modifica los datos
  cifrados, el descifrado falla en vez de devolver basura silenciosa.
- **Nonce único por cada cifrado**: nunca se reutiliza un nonce con la
  misma llave.
- **Nada en texto plano**: la contraseña maestra y la llave derivada
  solo existen en memoria durante la ejecución del programa.
- **Cambio de contraseña maestra sin pérdida de datos**: al cambiarla,
  todas las credenciales se descifran con la llave vieja y se vuelven
  a cifrar con la llave nueva antes de invalidar la anterior.

## Próximos pasos (roadmap)

- [ ] Generador de contraseñas seguras integrado
- [ ] Exportar/importar bóveda cifrada
- [ ] Tests unitarios
- [ ] Bloqueo automático por inactividad
