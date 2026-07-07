# Gestor de Contraseñas

Gestor de contraseñas de línea de comandos escrito en Python. Deriva una
llave a partir de una contraseña maestra con **PBKDF2-HMAC-SHA256** y
usa esa llave para cifrar/descifrar cada credencial guardada con
**AES-256-GCM**, almacenando todo en una base de datos **SQLite** local.

Parte de un portafolio de ciberseguridad orientado a hacer estas
herramientas accesibles para comunidades hispanohablantes.

## Por qué lo hice

Quería entender el cifrado más allá de la teoría: no solo saber que
"AES es seguro", sino tomar decisiones reales — cuántas iteraciones de
PBKDF2 son razonables, por qué GCM y no un modo de cifrado sin
autenticación, qué pasa si el usuario cambia su contraseña maestra sin
perder los datos ya guardados, cómo hacer un backup que siga siendo
seguro. Es el segundo proyecto de mi portafolio, pensado como
complemento del detector de phishing: mientras ese proyecto es sobre
detectar amenazas, este es sobre proteger datos.

## Qué hace y qué amenaza resuelve

Guarda credenciales (servicio, usuario, contraseña) sin depender de un
servicio en la nube ni de terceros. La amenaza que resuelve: reutilizar
la misma contraseña débil en todos lados, o guardar contraseñas en un
archivo de texto plano sin cifrar. Aquí, ni siquiera tú puedes ver las
contraseñas guardadas sin la contraseña maestra correcta, y el programa
te avisa activamente si alguna es débil o está repetida.

## Cómo funciona

1. **Primera vez**: se crea una contraseña maestra. Se genera un `salt`
   aleatorio y se deriva una llave de 256 bits con PBKDF2 (480,000
   iteraciones, recomendación OWASP). La contraseña maestra y la llave
   **nunca se guardan**; solo se guarda un "verificador" cifrado para
   confirmar la contraseña en futuros inicios.
2. **Cada inicio**: se pide la contraseña maestra, se deriva la llave
   otra vez con el mismo salt, y se intenta descifrar el verificador.
   Si el descifrado funciona, la contraseña es correcta. 3 intentos.
3. **Uso**: con la llave en memoria (solo durante la sesión activa) se
   pueden crear, ver, editar y borrar credenciales; generar contraseñas
   seguras automáticamente; revisar cuáles son débiles o están
   repetidas; exportar/importar un backup cifrado; y cambiar la
   contraseña maestra (re-cifrando todo automáticamente).
4. **Bloqueo por inactividad**: si pasan más de 2 minutos sin usar el
   menú, la sesión se bloquea y hay que volver a ingresar la
   contraseña maestra.

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

## Correr los tests

```bash
pytest tests/ -v
```

16 tests cubren: derivación de llave (determinismo, salt distinto ->
llave distinta), cifrado/descifrado (roundtrip, rechazo de llave
incorrecta, nonces únicos), generador de contraseñas, evaluación de
fortaleza, CRUD completo sobre SQLite, cambio de contraseña maestra
(verifica que la llave vieja quede invalidada y los datos se preserven
con la nueva), y exportar/importar backup.

## Estructura

```
password-manager/
├── password_manager.py       # Todo el programa: cripto, base de datos y CLI
├── tests/
│   └── test_password_manager.py
├── requirements.txt
├── .gitignore
├── LICENSE
└── vault.db                   # se crea automáticamente al correr el programa
                                # (no se sube a git)
```

## Decisiones de seguridad

- **PBKDF2-HMAC-SHA256, 480,000 iteraciones**: derivación de llave lenta
  a propósito para dificultar ataques de fuerza bruta offline.
- **AES-256-GCM**: cifrado autenticado; si alguien modifica los datos
  cifrados, el descifrado falla en vez de devolver basura silenciosa.
- **Nonce único por cada cifrado**: nunca se reutiliza un nonce con la
  misma llave.
- **`secrets` en vez de `random` para generar contraseñas**: `random`
  usa un generador predecible, no apto para criptografía; `secrets` usa
  el generador de números aleatorios del sistema operativo.
- **El backup exportado sigue cifrado**: exportar no descifra nada,
  solo convierte los bytes ya cifrados a base64 para que quepan en
  JSON. Sin la contraseña maestra original, el backup es tan inútil
  para un atacante como la base de datos misma.
- **Cambio de contraseña maestra sin pérdida de datos**: al cambiarla,
  todas las credenciales se descifran con la llave vieja y se vuelven
  a cifrar con la llave nueva antes de invalidar la anterior.

## Qué NO implementé (todavía)

- Sincronización entre dispositivos (es intencionalmente 100% local)
- Autocompletado o integración con navegador
- Verificación de si una contraseña apareció en una filtración conocida
  (tipo "Have I Been Pwned") — requeriría conexión a internet, y decidí
  mantener el programa completamente offline por ahora

## Próximos pasos (roadmap)

- [x] Diseño de esquema de datos + derivación de llave con PBKDF2
- [x] CRUD de contraseñas cifrado en SQLite
- [x] Generador de contraseñas seguras + validación de fortaleza
- [x] Tests unitarios
- [x] Exportación cifrada (backup) y reimportación
- [x] Detección de contraseñas reutilizadas o débiles
- [x] Bloqueo automático tras inactividad
- [ ] Grabar GIF de demo de 10-15s para este README
