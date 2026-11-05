# Brote Backup Bot — public controller

This repository contains generic backup code and synthetic tests only. Do not upload application code, configuration JSON, database dumps, backup assets or credentials here.

Daily backups and manual runs execute only on the approved commit of protected `main`, with Environment Secrets restricted to that branch. Lock `main` including administrators after reviewing the installed code. Set the repository variable `BACKUP_APPROVED_SHA` to the full reviewed commit SHA. Updating code requires explicit review, unlocking/relocking main and approving the new SHA. No second account or daily reviewer is required for an owner-operated frozen installation. This is owner review, not independent two-person approval.

Create `backup-production` and `backup-monitor` environments with Selected branches and tags: exactly branch `main`, no tags. Use no repository-level production secrets. Configuration remains an Environment Secret named `BACKUP_CONFIG` in both environments. Never paste it into Issues, workflow inputs, Variables, source code or PRs.

Actions exposes execution dates, workflow stages and success/failure publicly. Detailed status, backup/restore dates, object counts and notifications live exclusively in the private vault. The public summary contains no private links, hashes, names, counts or database contents. No backup artifacts are uploaded to public Actions. Exceptions from production tools are suppressed.

The manual operations are `daily`, `restore-latest` and `pre-migration`. The last operation consumes an immutable, hash-pinned private rehearsal specification; it executes the approved SQL only inside a disposable networkless PostgreSQL container. There is no remote migration or remote restore command.

GitHub Free supports protection and Environment Secrets for public repositories. A private repository using unrestricted repository Secrets does not provide the same boundary. This controller does not change visibility of any existing repository and requires no paid integration.

A monthly workflow without Environments or private secrets writes only the public month to `automation-heartbeat`, keeping activity off the locked code branch. Its temporary GITHUB_TOKEN can write this public repository; branch protection must include administrators, disable bypass, force pushes and deletion. It never writes main. Public scheduled workflows can be disabled after 60 days of inactivity; check Actions if the heartbeat fails. GitHub cron and provider outages have no guaranteed delivery. Private vault PATs require renewal; no system on these constraints can honestly promise zero maintenance forever.

Backup retention: 14 daily, 8 weekly, 6 monthly, pre-migration 30 days, `[KEEP]` releases indefinitely. Only encrypted assets go to private Releases. Releases are not WORM/PITR or a separate provider. Preserve the encryption password offline. Recovery of external Auth, Storage service configuration and keys needs a separately authorized administrative procedure.

## Configurar la CA PostgreSQL — pasos visuales

Supabase documenta `verify-full` con la **Server root certificate** de la sección SSL del proyecto, también para **Session pooler**. El certificado HTTPS que muestra el candado del navegador no es esa CA. Las referencias oficiales son [PSQL / Session pooler](https://supabase.com/docs/guides/database/psql) y [SSL enforcement](https://supabase.com/docs/guides/platform/ssl-enforcement).

1. Abre el Dashboard de Supabase y selecciona el proyecto correcto. En **Database → Settings → SSL Configuration**, pulsa **Download certificate / Server root certificate**. Según la versión del panel puede estar bajo Settings → Database. Descarga la CA actual que ofrece ese proyecto; no adivines un certificado por su nombre ni uses el candado del navegador. No cambies SSL enforcement: cambiarlo puede reiniciar la base. No restablezcas contraseñas.
2. Abre el archivo descargado con un editor de texto. Debe comenzar con `-----BEGIN CERTIFICATE-----` y terminar con `-----END CERTIFICATE-----`. Copia todo, incluidos esos delimitadores y saltos de línea reales. No pegues una ruta, una URL, comillas, una clave privada, base64 adicional ni caracteres literales `\n`. El archivo puede llamarse `prod-ca-2021.crt` o tener otro nombre; utiliza el ofrecido actualmente por el proyecto.
3. En GitHub, abre este controlador → **Settings → Environments → backup-production → Environment secrets → Add secret**. Name: **BACKUP_PG_CA_PEM**. Value: el contenido PEM completo. Guarda. Es un Secret nuevo: no edites los Secrets de host, usuario, contraseña, cifrado o tokens. No hace falta añadirlo a `backup-monitor` ni a los Secrets generales del repositorio.
4. No subas el certificado a Code, Issues, PRs, artifacts ni comentarios. Esta PR no contiene ningún certificado del proyecto. La CA se materializa solo en un directorio temporal privado (0700), fichero 0600, fuera del paquete de backup; se elimina al terminar, también si falla. No se descarga ni se aprende una CA automáticamente de un servidor sin verificar.
5. El mismo fichero se pasa como `sslrootcert` a psycopg y se monta **solo lectura** en Docker para `pg_dump`. La comprobación PostgreSQL posterior a la descarga de Storage utiliza también ese fichero. Todas las conexiones siguen en **sslmode=verify-full**: cadena y hostname se validan; no hay fallback al almacén del sistema ni a un modo más débil.

### Revisión, actualización y comprobación

Primero añade el Secret nuevo. Después desactiva temporalmente **Actions → Brote Backup Bot → … → Disable workflow**, revisa y fusiona esta PR siguiendo la ventana de desbloqueo de main, vuelve a bloquear main incluyendo administradores y actualiza **Settings → Secrets and variables → Actions → Variables → BACKUP_APPROVED_SHA** con el SHA completo del último commit resultante de main. No uses el SHA de otra rama ni uno de un repositorio privado. Solo entonces reactiva el workflow. Esta preparación no fusiona la PR, no desbloquea main, no configura Secrets y no ejecuta un backup real.

En el siguiente ensayo autorizado, `PG_CA_MISSING` significa que falta el Secret y `PG_CA_INVALID` que el PEM no se puede interpretar. Si continúa `PG_TLS_VERIFY`, revisa que la CA proceda del mismo proyecto y que el hostname sea exactamente el de **Connect → Session pooler**, puerto 5432. La categoría también puede incluir hostname incorrecto, cadena incompleta o certificado caducado: no demuestra por sí sola un error de contraseña. No reduzcas SSL a `require` ni desactives la verificación.

La documentación oficial identifica el origen de confianza para Session pooler. Sin usar las credenciales y el endpoint real no se puede acreditar aquí la cadena concreta instalada en ese servicio: la conexión real posterior debe superar cadena y hostname con la CA seleccionada. No se afirma que ya exista una copia de producción válida.

CI genera sus propias CA/certificados efímeros y usa PostgreSQL sintético con acceso por loopback/red dedicada: prueba psycopg y `pg_dump` con CA/hostname correctos y rechaza una CA ajena y un hostname incorrecto. Prueba también ausencia/PEM inválido y eliminación del fichero. No utiliza Secrets de Environment, credenciales reales ni certificados del proyecto. Los contenedores de restauración de producción siguen sin red.
