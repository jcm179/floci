# IAM seguro por defecto: plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el fork de Floci autentique y autorice por defecto, con credenciales root reales (generadas o por entorno), sin el comodín `test` ni `floci/floci`.

**Architecture:** Clases nuevas y pequeñas en el paquete `io.github.hectorvent.floci.security` (predicados estáticos configurados al arrancar, resolución pura de credenciales) y ganchos de una línea en el código existente. El root y el par interno del `floci-deployer` se guardan en el almacén de claves de acceso de `IamService`, de modo que todos los verificadores de firma existentes los encuentran sin cambios.

**Tech Stack:** Java 25, Quarkus 3.40, JUnit 5, RestAssured, Maven (`./mvnw`).

**Spec:** `docs/superpowers/specs/2026-10-30-secure-by-default-iam-design.md`

## Global Constraints

- Variables de entorno del root: `FLOCI_ROOT_ACCESS_KEY_ID` y `FLOCI_ROOT_SECRET_ACCESS_KEY`. Solo una de las dos: el arranque falla con un mensaje claro. Valor vacío o en blanco = no indicado.
- Par generado: access key id de 20 caracteres con prefijo `AKIA`; secret de 40 caracteres.
- El root generado se imprime una sola vez en el log, al crearse. El secret del `floci-deployer` nunca se imprime.
- Valores por defecto del fork, en `src/main/resources/application.yml`: `iam.enforcement-enabled=true`, `auth.validate-signatures=true`, `s3.enforce-auth=true`, `auth.allow-test-credentials=false`, `iam.seed-deployer-principal=true`, `storage.mode=persistent`.
- Conjunto estricto: ámbitos de credencial `s3`, `kms`, `secretsmanager`, `iam`, `sts`.
- Sin endpoints nuevos ni formas de petición nuevas (`AGENTS.md`).
- Los tests del upstream pasan con su configuración de test, que conserva el comportamiento permisivo.
- Cambios mínimos en archivos existentes: una línea por gancho, sin refactors.

## Review Focus

1. Solo una de las dos variables del root presente: el arranque falla (Task 4).
2. Root por entorno distinto del guardado: el par antiguo deja de firmar (Task 4).
3. Almacén persistente antiguo con la clave `floci`: se borra al arrancar y deja de firmar (Task 4).
4. URL prefirmada y POST de S3 con la clave `test`: se rechazan (Task 2).
5. Ruta REST sin acción mapeada en el conjunto estricto: se deniega; una operación `noAuth` de STS sin firma y el acceso anónimo a S3 que permite una política de recurso siguen funcionando (Task 5).

---

### Task 0: Entorno y línea base

**Files:** ninguno.

- [ ] **Step 1:** Crear la rama `feat/secure-by-default-iam` desde `docs/secure-by-default-iam-design`.
- [ ] **Step 2:** Ejecutar `java -version`. El proyecto compila con `release 25` (`pom.xml:16`). Si no hay JDK 25, instalarlo; si no se puede, parar y avisar a Jordi de que los tests habrá que ejecutarlos en su entorno.
- [ ] **Step 3:** Ejecutar `./mvnw -q test -Dtest=IamEnforcementFilterUnitTest`. Esperado: PASS. Es la línea base.

### Task 1: Claves de configuración y valores por defecto seguros

**Files:**
- Modify: `src/main/java/io/github/hectorvent/floci/config/EmulatorConfig.java` (interfaz `AuthConfig`, cerca de la línea 733)
- Modify: `src/main/resources/application.yml` (secciones `auth`, `services.s3`, `services.iam`, `storage`)
- Modify: `src/test/resources/application.yml`
- Test: `src/test/java/io/github/hectorvent/floci/security/SecureDefaultsConfigTest.java`

**Interfaces:**
- Produces: `AuthConfig.allowTestCredentials(): boolean` con `@WithDefault("true")`; `AuthConfig.denyUnmappedActions(): boolean` con `@WithDefault("false")`. Los valores de Java son permisivos para que los tests del upstream no cambien. El yml principal los pone en `false` y `true`.

- [ ] **Step 1: Escribir los tests.** `SecureDefaultsConfigTest` tiene dos casos. `mainApplicationYmlIsSecure` parsea `src/main/resources/application.yml` con SnakeYAML y comprueba `floci.auth.allow-test-credentials == false`, `floci.auth.deny-unmapped-actions == true`, `floci.auth.validate-signatures == true`, `floci.services.iam.enforcement-enabled == true`, `floci.services.iam.seed-deployer-principal == true`, `floci.services.s3.enforce-auth == true` y `floci.storage.mode == "persistent"`. `testProfileStaysPermissive` es un `@QuarkusTest` que inyecta `EmulatorConfig` y comprueba `auth().allowTestCredentials() == true`, `auth().denyUnmappedActions() == false` y `services().iam().enforcementEnabled() == false`.
- [ ] **Step 2:** Ejecutar `./mvnw -q test -Dtest=SecureDefaultsConfigTest`. Esperado: FAIL (los métodos no existen).
- [ ] **Step 3:** Añadir los dos métodos a `AuthConfig`. En `application.yml` principal, cambiar los valores listados en Global Constraints y añadir `floci.auth.root.access-key-id: ${FLOCI_ROOT_ACCESS_KEY_ID:}` y `floci.auth.root.secret-access-key: ${FLOCI_ROOT_SECRET_ACCESS_KEY:}`. En el `application.yml` de test, fijar de forma explícita los valores permisivos (`enforcement-enabled: false`, `validate-signatures: false`, `enforce-auth: false`, `allow-test-credentials: true`, `deny-unmapped-actions: false`, `seed-deployer-principal: false`) para no depender de la precedencia entre los dos archivos.
- [ ] **Step 4:** Ejecutar el test de nuevo. Esperado: PASS. Ejecutar además `IamEnforcementFilterUnitTest` y `SigV4HeaderSignatureIntegrationTest` para confirmar que la configuración de test sigue mandando.
- [ ] **Step 5:** Commit `feat(security): add secure-by-default config keys`.

### Task 2: La clave `test` deja de valer

**Files:**
- Create: `src/main/java/io/github/hectorvent/floci/security/LegacyTestCredentials.java`
- Create: `src/main/java/io/github/hectorvent/floci/security/SecureModeInitializer.java`
- Modify (una línea cada sitio, sustituyendo la comparación con `"test"` por `LegacyTestCredentials.accepts(...)`):
  - `core/common/IamEnforcementFilter.java:327` y `:1381`
  - `core/common/SigV4HeaderSignatureFilter.java:407` (`resolveSecretKey`)
  - `services/apigateway/ExecuteApiSigV4Authorizer.java:233` y `:254`
  - `services/s3/PreSignedUrlFilter.java:323`, `services/s3/S3PostPolicySigner.java:32`, `services/s3/S3Service.java:1625` y `:1649`
  - `services/lambdaweb/LambdaWebIamAuth.java` (`TEST_ACCESS_KEY`), `services/cloudtrail/CloudTrailService.java:884`, `services/appsync/graphql/auth/IamAuthValidator.java:320`
- Test: `src/test/java/io/github/hectorvent/floci/security/LegacyTestCredentialsTest.java`, `src/test/java/io/github/hectorvent/floci/security/SecureProfile.java`, `src/test/java/io/github/hectorvent/floci/security/TestKeyRejectedIntegrationTest.java`

**Interfaces:**
- Produces: `LegacyTestCredentials.accepts(String accessKeyId): boolean`, que es `true` solo si `accessKeyId` es `"test"` y no se ha configurado lo contrario (sin configurar, acepta, para no alterar los tests unitarios del upstream); `LegacyTestCredentials.configure(boolean allow): void`; `LegacyTestCredentials.resetForTests(): void`.
- Produces: `SecureProfile implements QuarkusTestProfile`, con overrides `floci.services.iam.enforcement-enabled=true`, `floci.auth.validate-signatures=true`, `floci.services.s3.enforce-auth=true`, `floci.auth.allow-test-credentials=false`, `floci.auth.deny-unmapped-actions=true`, `floci.services.iam.seed-deployer-principal=true`.
- Produces: `SecureModeInitializer`, un `@Startup @ApplicationScoped` que en su constructor lee `EmulatorConfig` y llama a `LegacyTestCredentials.configure` y a `StrictModePolicy.configure` (este último se crea en Task 5; hasta entonces solo configura el primero).

- [ ] **Step 1: Escribir los tests.** `LegacyTestCredentialsTest`: sin configurar, `accepts("test")` es `true`; tras `configure(false)`, `accepts("test")` es `false`; `accepts("AKIAXXXXXXXXXXXXXXXX")` es siempre `false`; `resetForTests()` restaura el valor por defecto. `TestKeyRejectedIntegrationTest` (`@QuarkusTest @TestProfile(SecureProfile.class)`): una petición firmada con `test/test` a SQS, otra a S3 (`ListBuckets`) y una URL prefirmada de S3 con la clave `test` se rechazan con 403. Reutilizar el firmador que ya usa `SigV4HeaderSignatureIntegrationTest`, sin escribir otro.
- [ ] **Step 2:** Ejecutar ambos tests. Esperado: FAIL.
- [ ] **Step 3: Implementar** `LegacyTestCredentials` y `SecureModeInitializer`, y aplicar el gancho en cada sitio de la lista. En cada uno es un cambio de una línea. Si al editar aparece otro sitio que compara con `"test"`, tratarlo igual (`grep -rn '"test"' src/main/java` al final de la tarea).
- [ ] **Step 4:** Ejecutar los dos tests, más `IamEnforcementFilterTest` y `SigV4HeaderSignatureIntegrationTest`. Esperado: PASS.
- [ ] **Step 5:** Commit `feat(security): reject the legacy test credential unless allowed`.

### Task 3: Generador de credenciales

**Files:**
- Create: `src/main/java/io/github/hectorvent/floci/security/KeyPair.java`
- Create: `src/main/java/io/github/hectorvent/floci/security/CredentialGenerator.java`
- Test: `src/test/java/io/github/hectorvent/floci/security/CredentialGeneratorTest.java`

**Interfaces:**
- Produces: `record KeyPair(String accessKeyId, String secretAccessKey)`.
- Produces: `CredentialGenerator(SecureRandom random)`; `newAccessKeyId(): String` (20 caracteres, prefijo `AKIA`, resto `[A-Z0-9]`); `newSecretAccessKey(): String` (40 caracteres de `[A-Za-z0-9/+]`).

- [ ] **Step 1: Escribir el test.** `CredentialGeneratorTest`: el id coincide con `^AKIA[A-Z0-9]{16}$`; el secret coincide con `^[A-Za-z0-9/+]{40}$`; mil ids generados no se repiten.
- [ ] **Step 2:** Ejecutar el test. Esperado: FAIL.
- [ ] **Step 3: Implementar** ambas clases. El generador solo usa el `SecureRandom` recibido.
- [ ] **Step 4:** Ejecutar el test. Esperado: PASS.
- [ ] **Step 5:** Commit `feat(security): add credential generator`.

### Task 4: Root real e identidad interna del deployer

**Files:**
- Create: `src/main/java/io/github/hectorvent/floci/security/RootCredentialBootstrap.java`
- Create: `src/main/java/io/github/hectorvent/floci/security/InternalCredentials.java`
- Modify: `services/iam/IamService.java` (`seedDefaults()` en la línea 674, `seedDefaultDeployerPrincipal()` en la 752, `resolveCallerArns` en la 5592; nuevos métodos públicos)
- Modify: `core/common/IamEnforcementFilter.java` (línea que define `accountRootKey`, cerca de la 363)
- Test: `src/test/java/io/github/hectorvent/floci/security/RootCredentialBootstrapTest.java`, `src/test/java/io/github/hectorvent/floci/security/RootCredentialsIntegrationTest.java`

**Interfaces:**
- Consumes: `KeyPair`, `CredentialGenerator` (Task 3).
- Produces: `RootCredentialBootstrap.Outcome(KeyPair root, boolean rootGenerated, KeyPair deployer, boolean deployerGenerated)` y `static Outcome resolve(Optional<String> envAccessKeyId, Optional<String> envSecretAccessKey, Optional<KeyPair> storedRoot, Optional<KeyPair> storedDeployer, CredentialGenerator generator)`. Reglas: si hay entorno completo, el root es el del entorno y `rootGenerated` es `false`; si hay solo una variable, lanza `IllegalStateException` con un mensaje que nombra las dos; sin entorno, reutiliza el guardado, y si no hay ninguno lo genera con `rootGenerated=true`. El deployer sigue la misma lógica sin entorno.
- Produces: `InternalCredentials.current(): Optional<KeyPair>`; `InternalCredentials.set(KeyPair): void`; `InternalCredentials.clear(): void`.
- Produces en `IamService`: `public static final String ROOT_PRINCIPAL_MARKER = "<root>"` (el `userName` de la clave del root); `public boolean isRootAccessKey(String accessKeyId)`; `public void replaceSeededAccessKey(String oldAccessKeyId, AccessKey key)`.

- [ ] **Step 1: Escribir los tests unitarios.** `RootCredentialBootstrapTest`: (a) sin entorno ni guardado, genera root y deployer con ambos flags `true`; (b) con guardados y sin entorno, devuelve los guardados con flags `false`; (c) con entorno completo y guardado distinto, devuelve el del entorno; (d) con solo `envAccessKeyId`, lanza `IllegalStateException` cuyo mensaje contiene `FLOCI_ROOT_SECRET_ACCESS_KEY`; (e) valores en blanco cuentan como no indicados; (f) el deployer nunca se toma del entorno.
- [ ] **Step 2: Escribir el test de integración.** `RootCredentialsIntegrationTest` (`@QuarkusTest @TestProfile(SecureProfile.class)`): `sts:GetCallerIdentity` firmado con el root generado devuelve `arn:aws:iam::000000000000:root`; con el root, `iam:CreateUser` funciona; con `floci/floci` la firma se rechaza; con el par interno, `s3:CreateBucket` funciona. El test lee los pares de la configuración de arranque; para obtener el root generado, usar un perfil con `FLOCI_ROOT_*` fijadas en `getConfigOverrides()` (`floci.auth.root.access-key-id` y `floci.auth.root.secret-access-key`). Añadir un caso con un almacén que contiene la clave `floci` heredada: tras arrancar, firmar con ella se rechaza.
- [ ] **Step 3:** Ejecutar ambos. Esperado: FAIL.
- [ ] **Step 4: Implementar** `resolve` (función pura) e `InternalCredentials`. En `IamService.seedDefaults()` añadir una llamada que lea la configuración con `ConfigProvider` (`floci.auth.root.*`), busque el root guardado escaneando el almacén de claves por `userName == ROOT_PRINCIPAL_MARKER`, llame a `resolve`, guarde el root con `AccessKey(accessKeyId, secret, ROOT_PRINCIPAL_MARKER)`, sustituya el root antiguo si cambió, borre la clave heredada `floci` si existe, y registre el par del deployer con `seedDefaultDeployerPrincipal(KeyPair)` (que deja de usar las constantes `floci/floci`). Después `InternalCredentials.set(deployer)`. Si el modo de almacenamiento efectivo es `memory` con el enforcement activo, un `LOG.warn` en `SecureModeInitializer` avisa de que el root se perderá en cada reinicio. Si `rootGenerated`, un único `LOG.infov` con el access key id y el secret, indicando que no se vuelven a mostrar. `resolveCallerArns` devuelve para el root un `CallerArns` de tipo `TYPE_ACCOUNT` con el ARN `arn:aws:iam::<cuenta>:root`. En el filtro, `accountRootKey` pasa a ser `akid.equals(accountId) || iamService.isRootAccessKey(akid)`.
- [ ] **Step 5:** Ejecutar ambos tests, más `IamEnforcementFilterTest` y la suite de `services/iam`. Esperado: PASS.
- [ ] **Step 6:** Commit `feat(security): bootstrap root and internal deployer credentials`.

### Task 5: Acciones sin mapear se deniegan en el conjunto estricto

**Files:**
- Create: `src/main/java/io/github/hectorvent/floci/security/StrictModePolicy.java`
- Modify: `src/main/java/io/github/hectorvent/floci/security/SecureModeInitializer.java` (ya existe; añadir la llamada de configuración)
- Modify: `core/common/IamEnforcementFilter.java` (las dos ramas con `action == null`: la que devuelve "REST route no rule maps → ALLOW", cerca de la 349, y la que devuelve "unknown action → ALLOW", cerca de la 395)
- Modify: `src/test/java/io/github/hectorvent/floci/services/iam/IamRestRouteCoverageTest.java`
- Test: `src/test/java/io/github/hectorvent/floci/security/StrictModePolicyTest.java`, `src/test/java/io/github/hectorvent/floci/security/StrictUnmappedActionIntegrationTest.java`

**Interfaces:**
- Produces: `StrictModePolicy.deniesUnmapped(String credentialScope): boolean`, `true` solo si está activada y el ámbito está en `s3`, `kms`, `secretsmanager`, `iam`, `sts`; `StrictModePolicy.configure(boolean enabled): void`; `StrictModePolicy.resetForTests(): void`. Sin configurar está desactivada.

- [ ] **Step 1: Escribir los tests.** `StrictModePolicyTest`: desactivada, `deniesUnmapped("s3")` es `false`; activada, es `true` para los cinco ámbitos y `false` para `sqs` y `lambda`. `StrictUnmappedActionIntegrationTest` (`SecureProfile`): una petición firmada con el root a una ruta REST inventada bajo el ámbito `s3` recibe 403 AccessDenied; `sts:AssumeRoleWithWebIdentity` sin firma no se rechaza por esta política; una lectura anónima de un objeto de un bucket con política pública sigue funcionando. Ampliar `IamRestRouteCoverageTest` para afirmar que ninguna operación de S3, KMS, Secrets Manager, IAM y STS que Floci sirve queda sin acción mapeada.
- [ ] **Step 2:** Ejecutar los tres. Esperado: FAIL.
- [ ] **Step 3: Implementar** `StrictModePolicy` y, en cada una de las dos ramas del filtro, antes del `return` permisivo: si `StrictModePolicy.deniesUnmapped(credentialScope)`, abortar con `accessDeniedForRequest("Unknown", credentialScope, ctx)` y devolver. Si la ampliación de `IamRestRouteCoverageTest` revela operaciones sin mapear, añadir sus reglas a `IamActionRegistry`.
- [ ] **Step 4:** Ejecutar los tres tests y la suite de `core/common` e `iam`. Esperado: PASS.
- [ ] **Step 5:** Commit `feat(security): deny unmapped actions for s3, kms, secretsmanager, iam and sts`.

### Task 6: Procesos que lanza Floci usan el par interno

**Files:**
- Modify: `core/common/docker/LaunchedContainerAwsEnv.java` (rama de credenciales por defecto, cerca de la línea 168)
- Modify: `services/ec2/Ec2ContainerManager.java:1687`, `services/sagemaker/SageMakerTrainingRunner.java:215`, `services/sagemaker/SageMakerEndpointManager.java:189`
- Modify: el código que arranca los procesos de los init hooks, en `lifecycle/inithook/` (localizar con `grep -rn ProcessBuilder src/main/java/io/github/hectorvent/floci/lifecycle/inithook`)
- Test: `src/test/java/io/github/hectorvent/floci/core/common/docker/LaunchedContainerAwsEnvInternalCredentialsTest.java`, `src/test/java/io/github/hectorvent/floci/security/InitHookCredentialsTest.java`

**Interfaces:**
- Consumes: `InternalCredentials.current(): Optional<KeyPair>`, `LegacyTestCredentials.accepts(String)`.

- [ ] **Step 1: Escribir los tests.** `LaunchedContainerAwsEnvInternalCredentialsTest`: con `InternalCredentials.set(new KeyPair("AKIAAAAAAAAAAAAAAAAA", "s"))` y `LegacyTestCredentials.configure(false)`, `sdkBaselineEnv(...)` sin credenciales de sesión devuelve `AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA` y `AWS_SECRET_ACCESS_KEY=s` y no incluye `AWS_SESSION_TOKEN`; con `LegacyTestCredentials` sin configurar devuelve `test` como hoy. `InitHookCredentialsTest`: el entorno de un proceso de init hook contiene las dos variables con el par interno cuando está establecido.
- [ ] **Step 2:** Ejecutar ambos. Esperado: FAIL.
- [ ] **Step 3: Implementar.** En cada sitio, cuando `InternalCredentials.current()` tiene valor y `LegacyTestCredentials.accepts("test")` es `false`, inyectar ese par y omitir `AWS_SESSION_TOKEN`; en caso contrario, el comportamiento actual. El `ENV AWS_ACCESS_KEY_ID=test` de `docker/Dockerfile:21` se deja: el entorno del hook lo sobrescribe.
- [ ] **Step 4:** Ejecutar ambos tests y los tests existentes de `LaunchedContainerAwsEnv`, EC2 y SageMaker. Esperado: PASS.
- [ ] **Step 5:** Commit `feat(security): launched workloads use the internal credential`.

### Task 7: Documentación y comprobación de extremo a extremo

**Files:**
- Create: `docs/configuration/secure-mode.md`
- Modify: `mkdocs.yml` (entrada de navegación), `README.md` (nota breve en Quick Start sobre el root generado)
- Test: `src/test/java/io/github/hectorvent/floci/security/SecureModeEndToEndIntegrationTest.java`

- [ ] **Step 1: Escribir el test de extremo a extremo** (`@QuarkusTest @TestProfile(SecureProfile.class)`, root fijado por entorno en el perfil): el root crea un bucket; el root crea un usuario con una política que solo permite `s3:GetObject` sobre ese bucket; el usuario lee un objeto y recibe AccessDenied al escribirlo; lo mismo para una clave KMS (`kms:Decrypt` permitido, `kms:Encrypt` denegado) y para un secreto (`secretsmanager:GetSecretValue` permitido, `PutSecretValue` denegado); `test/test` y `floci/floci` se rechazan.
- [ ] **Step 2:** Ejecutar el test. Esperado: FAIL si falta algo de las tareas anteriores; si PASS, el comportamiento ya está cubierto y se conserva como prueba de regresión.
- [ ] **Step 3:** Escribir `secure-mode.md`: qué cambia respecto a Floci, las variables `FLOCI_ROOT_*`, cómo se muestra el root una vez, la recuperación (entorno o borrar datos), el par interno, las limitaciones (una cuenta, sin autenticación IAM a nivel de motor para DocumentDB y similares, almacenamiento actual).
- [ ] **Step 4: Comprobación manual de persistencia.** Arrancar el jar con `FLOCI_STORAGE_PERSISTENT_PATH` en un directorio temporal, anotar el root del log, parar, arrancar de nuevo y comprobar que el log no muestra otro root y que `aws sts get-caller-identity` con el mismo par funciona; luego arrancar con `FLOCI_ROOT_ACCESS_KEY_ID` y `FLOCI_ROOT_SECRET_ACCESS_KEY` distintos y comprobar que el par anterior se rechaza.
- [ ] **Step 5:** Ejecutar la suite completa con `./mvnw test`. Esperado: PASS.
- [ ] **Step 6:** Commit `docs(security): document secure mode and add end-to-end test`.
