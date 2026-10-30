# Diseño: IAM seguro por defecto con credenciales root reales

Fecha: 2026-10-30. Repositorio: fork `jcm179/floci`. Estado: borrador pendiente de aprobación.

## Intención y por qué

Jordi usa Floci para probar y experimentar, pero quiere un emulador de AWS que se comporte como AWS real en seguridad: nada se accede sin autenticarse y nada se hace sin que una política IAM lo permita. Hoy Floci es permisivo por defecto: cualquier credencial no vacía vale, y la clave `test` se salta el control. El mecanismo de enforcement ya existe, pero está apagado y tiene atajos. Este diseño lo convierte en el comportamiento por defecto del fork.

Un requisito de método: el fork debe poder seguir fusionando cambios del upstream (Floci es muy activo). Por eso los cambios se hacen como clases nuevas con ganchos mínimos en el código existente.

## Lo que ya existe (no hay que construirlo)

- `IamEnforcementFilter` (`core/common`): evalúa políticas de identidad, session policies, permissions boundaries y políticas de recurso. Se activa con `floci.services.iam.enforcement-enabled`, hoy `false`.
- `SigV4HeaderSignatureFilter` y los filtros de S3: verifican la firma SigV4 con `floci.auth.validate-signatures`, hoy `false`. S3 tiene además `floci.services.s3.enforce-auth`.
- `IamService.seedDefaults()` (`@PostConstruct`): ya siembra datos si faltan. `seedDeployerPrincipal` crea el usuario `floci-deployer` con clave `floci/floci` en el almacén `iam-access-keys.json`. Es el modelo a seguir para el root.
- Tests de enforcement por ARN para KMS y Secrets Manager, y de enforcement general del filtro.

## Objetivos

1. Con la configuración por defecto del fork, toda petición se autentica (firma verificada) y se autoriza (política evaluada). Sin credenciales válidas no hay acceso.
2. Credenciales root reales:
   - Si no se indica nada, se generan en el primer arranque (access key id y secret) y se guardan.
   - Si se pasan por variables de entorno, se usan esas. Si ya había unas guardadas, las del entorno las sustituyen.
   - Se crean solo cuando no existen. En arranques posteriores se reutilizan las guardadas.
   - Recuperar el acceso perdido se hace solo de dos maneras: pasar root por entorno, o borrar los datos. No se añade ningún endpoint de recuperación.
3. Desde el root se pueden crear usuarios y roles con políticas, y esas políticas se aplican de verdad.
4. Prioridad de servicios: S3, KMS, Secrets Manager, IAM, y STS porque la autenticación depende de él (`GetCallerIdentity`, `AssumeRole`). Para estos, lo que no se sepa mapear a una acción se deniega en lugar de permitirse.
5. El resto del upstream sigue pasando sus tests con un perfil de tests propio.

## No objetivos

- Un motor de almacenamiento nuevo (base de datos, Redis). Se hará después y por separado.
- Autenticación IAM a nivel de motor para servicios como DocumentDB, ElastiCache o MSK (la conexión a la base de datos). Es deseable para más adelante. RDS ya tiene un proxy que valida tokens IAM.
- Cerrar los huecos de los demás servicios de la API (rutas REST sin regla). Fase posterior.
- Roots por cuenta en un entorno multi-cuenta. Solo la cuenta por defecto.
- MFA del root, consola, o cualquier endpoint personalizado. Floci debe mantener los protocolos AWS reales (regla de `AGENTS.md`).

## Anti-objetivos (fallos aunque "funcione")

- Un camino silencioso en el que el emulador acepte credenciales falsas pareciendo seguro.
- Imprimir el secret del root en cada arranque.
- Divergir tanto del upstream que fusionar sea doloroso.

## Restricciones

- Java 25, Quarkus; capas Controller, Service, Model; reutilizar patrones de Floci y respetar `AGENTS.md`.
- El almacenamiento actual (memory, persistent, hybrid, wal sobre archivos JSON) no cambia. La imagen oficial arranca en `memory`.

## Enfoque elegido: capa aparte con ganchos mínimos

Se evaluaron: (1) modificar el filtro en el sitio, (2) capa aparte con ganchos mínimos, (3) un proxy de autenticación delante. Se descartó el 3 porque duplicaría el estado de IAM, y Jordi eligió el 2 para poder seguir el upstream.

Clases nuevas (nombres orientativos):
- `RootCredentialBootstrap`: genera o recibe el root, lo registra en el almacén de claves de acceso del IAM existente y decide qué hacer en cada arranque.
- `StrictModePolicy`: decide si una petición sin acción mapeada se deniega, según el servicio.

Ganchos en código existente, todos pequeños:
- `IamEnforcementFilter.filter()`: la rama `"test".equals(akid)` pasa a depender de un flag `floci.auth.allow-test-credentials`.
- `IamEnforcementFilter`, el segundo uso de `"test"` en el método de autorización de recursos adicionales: mismo flag.
- La rama "REST route no rule maps → ALLOW" y las acciones sin resolver: consultan `StrictModePolicy`.
- `IamService.seedDefaults()`: una llamada a `RootCredentialBootstrap`.

### Quién llama a Floci y qué se ve afectado

- **Peticiones sin firma legítimas.** El filtro ya distingue las operaciones que AWS sirve sin credenciales (`noAuth`, como `AssumeRoleWithWebIdentity` y `AssumeRoleWithSAML`), las URL prefirmadas y el acceso anónimo a S3 que una política de recurso permite. Nada de eso cambia. `StrictModePolicy` solo actúa sobre peticiones firmadas cuyo ámbito de credencial sea `s3`, `kms`, `secretsmanager`, `iam` o `sts`, y solo en la rama de acción sin mapear. Los endpoints que no son API (salud, OIDC, runtime de Lambda, function URLs, ejecución de API Gateway) quedan fuera.
- **Llamadas de servicio a servicio** (por ejemplo SES publicando en SNS) no pasan por el filtro: las decide `ServiceCallAuthorizer` con la política de recurso. No cambian.
- **Contenedores que Floci lanza.** EC2, SageMaker y ECS inyectan hoy `AWS_ACCESS_KEY_ID=test`, que dejará de valer. En esta fase se documenta como limitación conocida y no se les inyecta el root. Los scripts de inicialización (init hooks) sí reciben las credenciales root, porque los escribe el operador.
- **`floci-deployer`** (clave `floci/floci`) sigue apagado por defecto (`seed-deployer-principal=false`). Si alguien lo activa, es una decisión explícita con una clave conocida, y la documentación lo advierte.

Valores por defecto del fork: `iam.enforcement-enabled=true`, `auth.validate-signatures=true`, `s3.enforce-auth=true`, `allow-test-credentials=false`. Los tests del upstream corren con un perfil de test que los deja como antes y pone `allow-test-credentials=true`.

## Decisiones

Dichas por Jordi:
- El comportamiento seguro es el predeterminado del fork, no un modo opcional.
- Root: generado en el primer arranque o por entorno; guardado; el entorno lo sobrescribe; recuperación solo por entorno o borrando datos.
- Servicios prioritarios: S3, KMS, Secrets Manager, IAM.

Mías (a confirmar al leer):
- Nombres de variables: `FLOCI_ROOT_ACCESS_KEY_ID` y `FLOCI_ROOT_SECRET_ACCESS_KEY`. Si solo viene una de las dos, el arranque falla con un mensaje claro.
- El root generado se muestra una sola vez en el log, en el momento de crearse, y no se escribe en ningún otro sitio. Si se pierde el log, se recupera con las dos vías de arriba.
- Formato del par generado: access key id de 20 caracteres con prefijo `AKIA`, secret de 40 caracteres.
- El root es una identidad de tipo cuenta (`arn:aws:iam::<cuenta>:root`) con acceso total, sin usuario IAM detrás, como ya se trata hoy el stand-in de root.
- Como un root solo en memoria se perdería en cada reinicio, el fork arranca con almacenamiento `persistent` por defecto. Se avisa en el log si se configura `memory` con enforcement activo.
- STS entra en el conjunto estricto por depender de él la autenticación.
- Los init hooks reciben las credenciales root; EC2, SageMaker y ECS quedan para una fase posterior.
- `floci-deployer` no cambia: sigue apagado por defecto.

## Criterios de éxito

- Arranque limpio con la configuración por defecto: el log muestra el root; `aws s3 mb` firmado con ese par funciona.
- La misma llamada con `test/test`, o con una clave inventada, se rechaza.
- Con el root se crea un usuario con una política que solo permite `s3:GetObject` sobre un bucket: puede leer y no puede escribir (AccessDenied). Lo mismo se comprueba para KMS y Secrets Manager.
- Un reinicio en modo `persistent` conserva el root y no genera otro. Pasar otro par por entorno lo sustituye. Borrar los datos genera uno nuevo.
- La suite del upstream pasa con el perfil de tests.

## Deja al constructor

- El mecanismo exacto para fijar los valores por defecto del fork evitando líneas que el upstream edita a menudo (comprobar la precedencia de las fuentes de configuración de Quarkus).
- Comprobar que una clave de acceso sin usuario detrás se evalúa como root completo en el evaluador y en cada servicio prioritario.
- La lista concreta de rutas REST y acciones de S3, KMS, Secrets Manager, IAM y STS que hay que cubrir, a partir de `IamActionRegistry` y sus tests de cobertura.
- Estructura de paquetes y nombres definitivos de las clases nuevas.
