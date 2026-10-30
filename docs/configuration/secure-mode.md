# Secure Mode

This fork of Floci is secure by default. Requests to S3, KMS, Secrets Manager, IAM and STS must carry
a valid SigV4 signature and are authorized against IAM policies. There is no switch to turn on: the
settings of the main `application.yml` are already the secure ones.

Coverage is not yet complete in this phase. S3 is covered by `enforce-auth`; KMS, Secrets Manager, IAM
and STS (JSON and Query protocols) are refused when unsigned. Unsigned REST calls to other services
(Lambda, API Gateway management, EKS, Route 53 and similar) are still served; covering them is a later
phase. The `/_floci/*` management endpoints are unauthenticated. See [Limitations](#limitations).

## What changes compared with upstream Floci

| Setting | Upstream default | This fork |
|---|---|---|
| `floci.services.iam.enforcement-enabled` | `false` | `true` |
| `floci.auth.validate-signatures` | `false` | `true` |
| `floci.services.s3.enforce-auth` | `false` | `true` |
| `floci.auth.allow-test-credentials` | accepts `test` | `false` |
| `floci.auth.deny-unmapped-actions` | not present | `true` |
| `floci.services.iam.seed-deployer-principal` | `false` | `true` |
| `floci.storage.mode` | `memory` | `persistent` |

Consequences:

- A made-up access key, an unsigned management call, and the old `test` / `test` pair are rejected.
- The old `floci` / `floci` deployer pair is rejected too. A `floci` key found in a store written by
  an older version is deleted at startup.
- Policies attached to IAM users and roles are evaluated for real. A user with no policy can do
  nothing.
- The upstream test suite keeps running with permissive values: the test `application.yml` pins
  `validate-signatures`, `enforce-auth` and `enforcement-enabled` to `false`, `allow-test-credentials`
  to `true`, `deny-unmapped-actions` to `false` and `seed-deployer-principal` to `false`.

## The root credentials

Floci creates the account root credentials the first time it starts with an empty IAM store, and
reuses the stored pair on every later start.

- The access key id has 20 characters and starts with `AKIA`. The secret has 40 characters.
- The pair is written to the log once, at the moment it is generated, in a line that starts with
  `Generated root credentials for account`. It is not written to the log again (the root is stored in plaintext in the IAM access key store).
- The root is the account root of the default account (`arn:aws:iam::<account>:root`). It has full
  access and no IAM user behind it. `aws sts get-caller-identity` answers with the root ARN.

```bash
export AWS_ACCESS_KEY_ID=AKIA...        # from the startup log
export AWS_SECRET_ACCESS_KEY=...        # from the startup log
aws --endpoint-url http://localhost:4566 s3 mb s3://my-bucket
```

### Choosing the root yourself

Set both variables and Floci uses that pair instead of generating one:

| Variable | Meaning |
|---|---|
| `FLOCI_ROOT_ACCESS_KEY_ID` | Access key id of the root |
| `FLOCI_ROOT_SECRET_ACCESS_KEY` | Secret access key of the root |

- Setting only one of the two stops Floci at startup with an error that names both variables.
- A pair given by environment replaces any root stored earlier, and a stored root of the same
  id is reactivated if it had been deactivated.
- The environment pair is read at every start, so it also works with `memory` storage.

### Recovering lost root credentials

There is no recovery endpoint. There are two ways back in:

1. Start Floci with `FLOCI_ROOT_ACCESS_KEY_ID` and `FLOCI_ROOT_SECRET_ACCESS_KEY` set. The pair you give
   becomes the root and the previous one stops working.
2. Delete the data directory (`FLOCI_STORAGE_PERSISTENT_PATH`, `./data` by default). The next start
   generates a new root. This also deletes everything else Floci had stored.

## Creating users and roles

The root can create users, roles and policies, and the policies are enforced:

```bash
aws iam create-user --user-name reader
aws iam put-user-policy --user-name reader --policy-name read-reports --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"}]
}'
aws iam create-access-key --user-name reader
```

With that key, `aws s3 cp s3://reports/a.txt .` works and `aws s3 cp a.txt s3://reports/` fails with
`AccessDenied`. The same holds for KMS (`kms:Decrypt` allowed, `kms:Encrypt` denied, answered as
`AccessDeniedException`) and Secrets Manager (`GetSecretValue` allowed, `PutSecretValue` denied).
`SecureModeEndToEndIntegrationTest` checks all three.

## The internal deployer pair

Floci seeds an IAM user named `floci-deployer` with the `AdministratorAccess` managed policy and a
random access key pair. The pair is generated once, stored, never printed, and reused on later starts.
Nobody receives it. Floci uses it for the processes it launches itself:

- initialization hooks (scripts in the init directory),
- containers and runtimes that Floci starts, such as EC2 instances without an instance profile,
  SageMaker training jobs and endpoints, Batch, CodeBuild, Lambda and the DuckDB container.

The Floci web console is not on this list. It is unauthenticated, so in secure mode it receives no
usable credentials (placeholder values only). To let it call Floci, supply credentials through its
extra-env setting.

Three consequences to be aware of:

### Exposure

Workloads launched without a role receive the internal deployer pair with `AdministratorAccess`: EC2
without an instance profile, ECS, Batch, CodeBuild and SageMaker jobs, and Lambda functions whose
execution role credentials cannot be resolved. A user who is allowed only to start a task, instance,
build or job can therefore read administrator keys from the container environment and call Floci as an
administrator. This is a known limitation of this phase. Do not run code you do not trust in a
secure-mode Floci, and treat permission to start such workloads as administrator access.

!!! note "Tenancy"
    In secure mode, launched containers and the DuckDB container authenticate as the deployer user
    of the default account. They no longer present the owner account of the resource that started
    them, so in a multi-account setup their calls are attributed to the default account. Queries for
    a non-default account that go through DuckDB (Redshift Spectrum, CUR) read the default account's
    buckets, not just the wrong attribution: they return the wrong data.

### Emulator reset

`/_floci/state/reset` and `/nuke` wipe the stores but keep the root key and the deployer user, policy
and key, so signing keeps working afterwards.

## Strict mode for unmapped actions

With `floci.auth.deny-unmapped-actions=true`, a signed request whose credential scope is `s3`, `kms`,
`secretsmanager`, `iam` or `sts` is denied with `AccessDenied` when Floci cannot map it to an IAM
action. Other services keep their previous behavior: an unmapped REST route is allowed.

- Unsigned requests, operations AWS serves without credentials (for example
  `AssumeRoleWithWebIdentity`), presigned URLs and anonymous S3 reads that a resource policy allows are
  not affected.
- S3 `DeleteObjects` (`POST /{bucket}?delete`) and browser-form `PostObject` are exempt from the
  route check, because no single action maps them. `S3Controller` authorizes each key itself.
- CORS preflight (`OPTIONS`) is never denied by this rule.
- Signature verification runs before authorization. A request signed with an unknown access key
  is therefore turned away with `InvalidAccessKeyId` by the signature filters on the routes they
  cover. Inside the IAM filter the strict denial is evaluated before the key is looked up, so an
  unknown key on an unmapped strict-scope route that signature verification does not cover gets
  `AccessDenied`, not `InvalidAccessKeyId`.

## Storage: memory or persistent

The effective default of this fork is `persistent`, set in the main `application.yml`
(`floci.storage.mode`), with the data under `./data` (`/app/data` in the Docker images).

- In `persistent`, `hybrid` and `wal` modes the generated root is stored and survives a restart.
- In `memory` mode the generated root is lost on every restart, and a new one is generated and
  logged. Floci logs a warning at startup when enforcement is on and IAM runs in `memory` mode. To keep
  one root across restarts in `memory` mode, set `FLOCI_ROOT_ACCESS_KEY_ID` and
  `FLOCI_ROOT_SECRET_ACCESS_KEY`.
- Running in a container needs a volume on the data directory, or the container's own filesystem is
  the only place the root is kept.

!!! note
    Other pages of this documentation, and the environment variable tables in the README, still say
    that `FLOCI_STORAGE_MODE` defaults to `memory`. That is the upstream default. This fork's
    `application.yml` sets `persistent`; a `FLOCI_STORAGE_MODE` you set always wins.

## Verify persistence

These steps need a built jar and cannot be replaced by the automated tests. Adjust the jar path to
your build.

1. Start Floci with a temporary data directory and note the root from the log:

    ```bash
    export DATA=$(mktemp -d)
    FLOCI_STORAGE_PERSISTENT_PATH=$DATA java -jar target/quarkus-app/quarkus-run.jar
    ```

    Copy the access key id and secret from the line `Generated root credentials for account`.

2. Check that the pair works, then stop Floci:

    ```bash
    AWS_ACCESS_KEY_ID=<id> AWS_SECRET_ACCESS_KEY=<secret> \
      aws --endpoint-url http://localhost:4566 sts get-caller-identity
    ```

3. Start Floci again with the same `FLOCI_STORAGE_PERSISTENT_PATH`. The log must not show a new
   `Generated root credentials` line, and the `get-caller-identity` call above must still work with
   the same pair.

4. Stop Floci and start it with a different pair:

    ```bash
    FLOCI_STORAGE_PERSISTENT_PATH=$DATA \
    FLOCI_ROOT_ACCESS_KEY_ID=AKIAEXAMPLEOFANEWROOT \
    FLOCI_ROOT_SECRET_ACCESS_KEY=a-new-secret-of-your-choosing \
      java -jar target/quarkus-app/quarkus-run.jar
    ```

    The first pair must now be rejected, and the new one must work.

## Limitations

- Only the default account has a root. Roots per account are not supported.
- IAM authentication at the engine level is not provided for DocumentDB, ElastiCache, MSK and
  similar services (the connection to the database). RDS keeps its existing token-validating proxy.
- Strict mode covers S3, KMS, Secrets Manager, IAM and STS. Unmapped REST routes of other services
  are still allowed.
- Not every request must be signed in this phase. Unsigned REST calls to services other than S3, KMS,
  Secrets Manager, IAM and STS (Lambda, API Gateway management, EKS, Route 53 and similar) are still
  served; this is a non-goal of the first phase and is left to a later one. The `/_floci/*`
  management endpoints are unauthenticated.
- Workloads launched without a role receive the administrator internal pair; see
  [Exposure](#exposure).
- Storage is the existing file-based storage (`memory`, `persistent`, `hybrid`, `wal`). The root and
  the internal pair are stored in the IAM access key store in the clear.
