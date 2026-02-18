# Generador de certificados eIDAS para pruebas

## Perfiles disponibles

| Archivo | Tipo | Basado en | Validez |
|---------|------|-----------|---------|
| `eidas-cert.cnf` | Representante Persona Jurídica | AC Representación (FNMT-RCM) | 730 días (2 años) |
| `eidas-cert-persona-fisica.cnf` | Persona Física (Ciudadano) | AC FNMT Usuarios | 1460 días (4 años) |
| `eidas-cert-isbe-foundation.cnf` | Otro perfil | — | — |

## Paso 1 — Genera el certificado

Representante de Persona Jurídica (perfil FNMT AC Representación):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout mykey.pem -out mycert.pem -days 730 -sha256 -config eidas-cert.cnf
```

Persona Física / Ciudadano (perfil FNMT AC Usuarios):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout mykey.pem -out mycert.pem -days 1460 -sha256 -config eidas-cert-persona-fisica.cnf
```

Otro perfil:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout mykey.pem -out mycert.pem -days 365 -sha256 -config eidas-cert-isbe-foundation.cnf
```

## Paso 2 — Genera el .pfx

```bash
openssl pkcs12 -export -out mycert.pfx -inkey mykey.pem -in mycert.pem
```

## Paso 3 — Instala el certificado en tu navegador

### macOS (Chrome / Safari / Edge)

1. Haz doble clic en el archivo `.pfx`
2. Se abre **Acceso a Llaveros** (Keychain Access)
3. Introduce la contraseña que usaste al crear el `.pfx` (o vacía si no pusiste ninguna)
4. El certificado se instala en el llavero "inicio de sesión"

### Windows (Chrome / Edge)

1. Haz doble clic en el archivo `.pfx`
2. Se abre el **Asistente para importar certificados**
3. Selecciona "Usuario actual" y haz clic en Siguiente
4. Introduce la contraseña del `.pfx`
5. Almacena en: **Personal** > Finalizar

### Firefox (todos los SO)

Firefox usa su propio almacén de certificados:

1. Abre **Ajustes** > **Privacidad y seguridad** > **Certificados** > **Ver certificados**
2. Pestaña **Sus certificados** > **Importar**
3. Selecciona el archivo `.pfx` e introduce la contraseña

### Prueba en el prototipo

El selector de certificados del navegador solo aparece en `https://cert.eudistack.net/`.
Al acceder, el navegador mostrará el diálogo nativo para seleccionar un certificado cliente.

En desarrollo local (`localhost`), se usa un selector simulado sin certificado real.

## Paso 4 — Verifica el contenido (opcional)

```bash
openssl x509 -in mycert.pem -text -noout
```
