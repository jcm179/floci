#!/usr/bin/env bash
# Smoke test of a built Floci image in secure-by-default mode.
#
#   .github/ci/secure-smoke.sh IMAGE
#
# Runs the image as a user would (generated root, restart, root from the environment) and
# checks the behaviour the secure mode promises: a generated root that works and is printed
# once, rejection of the legacy test pair, floci/floci and invented keys, a restricted IAM user
# that can read but not write, persistence across a restart, and replacement by environment.
# Needs docker, curl and the AWS CLI v2 (all present on ubuntu-latest runners).
set -uo pipefail

IMAGE="${1:?usage: secure-smoke.sh IMAGE}"
NAME=floci-smoke
VOLUME=floci-smoke-data
PORT="${FLOCI_SMOKE_PORT:-4566}"
ENDPOINT="http://localhost:${PORT}"
WORK="$(mktemp -d)"

export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
unset AWS_SESSION_TOKEN AWS_PROFILE

FAILURES=0
SECRETS=()

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Container logs with every secret this script knows replaced, so a public CI log never carries one.
safe_logs() {
    local text
    text="$(docker logs "$NAME" 2>&1)"
    local secret
    for secret in "${SECRETS[@]}"; do
        [ -n "$secret" ] && text="${text//"$secret"/<redacted>}"
    done
    printf '%s\n' "$text"
}

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

# aws_as ACCESS_KEY SECRET_KEY args...
aws_as() {
    local access_key="$1" secret_key="$2"
    shift 2
    AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" \
        aws --endpoint-url "$ENDPOINT" "$@"
}

expect_ok() {
    local description="$1"
    shift
    if "$@" >"$WORK/out" 2>&1; then
        pass "$description"
    else
        fail "$description"
        sed 's/^/    /' "$WORK/out"
    fi
}

expect_denied() {
    local description="$1"
    shift
    if "$@" >"$WORK/out" 2>&1; then
        fail "$description (the call succeeded, it must be rejected)"
        sed 's/^/    /' "$WORK/out"
    else
        pass "$description"
    fi
}

start_container() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" -p "${PORT}:4566" -v "${VOLUME}:/app/data" "$@" "$IMAGE" >/dev/null
}

wait_ready() {
    local attempt
    for attempt in $(seq 1 90); do
        if curl -fsS "${ENDPOINT}/_floci/init" 2>/dev/null | grep -q '"ready":true'; then
            return 0
        fi
        sleep 1
    done
    fail "the container did not become ready within 90 seconds"
    safe_logs | tail -n 60
    return 1
}

finish() {
    echo
    if [ "$FAILURES" -eq 0 ]; then
        echo "Secure smoke test passed."
        exit 0
    fi
    echo "Secure smoke test failed: ${FAILURES} check(s)."
    echo "---- container logs (secrets redacted) ----"
    safe_logs | tail -n 120
    exit 1
}

# 1. First start without any root configured: Floci generates one and prints it once.
echo "== First start, generated root =="
docker volume create "$VOLUME" >/dev/null
start_container
wait_ready || finish

FIRST_LOGS="$(docker logs "$NAME" 2>&1)"
ROOT_KEY=""
ROOT_SECRET=""
if [[ "$FIRST_LOGS" =~ access\ key\ id\ (AKIA[A-Z0-9]{16}),\ secret\ access\ key\ ([A-Za-z0-9/+]{40})\. ]]; then
    ROOT_KEY="${BASH_REMATCH[1]}"
    ROOT_SECRET="${BASH_REMATCH[2]}"
    SECRETS+=("$ROOT_SECRET")
    pass "the generated root is printed in the log"
else
    fail "no generated root credentials found in the log"
    safe_logs | tail -n 60
    finish
fi

# 2. The root works, and everything that used to work does not.
echo "== Authentication =="
expect_ok "root: sts get-caller-identity" aws_as "$ROOT_KEY" "$ROOT_SECRET" sts get-caller-identity
expect_ok "root: s3 create bucket" aws_as "$ROOT_KEY" "$ROOT_SECRET" s3api create-bucket --bucket smoke-bucket
expect_denied "test/test is rejected" aws_as test test sts get-caller-identity
expect_denied "floci/floci is rejected" aws_as floci floci sts get-caller-identity
expect_denied "an invented key is rejected" \
    aws_as AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY sts get-caller-identity
expect_denied "test/test is rejected on S3" aws_as test test s3api list-buckets

UNSIGNED_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT/" \
    -H 'Content-Type: application/x-amz-json-1.1' \
    -H 'X-Amz-Target: secretsmanager.ListSecrets' -d '{}')"
if [[ "$UNSIGNED_CODE" =~ ^4[0-9][0-9]$ ]]; then
    pass "an unsigned Secrets Manager call is refused (HTTP ${UNSIGNED_CODE})"
else
    fail "an unsigned Secrets Manager call returned HTTP ${UNSIGNED_CODE}, expected a 4xx"
fi

# 3. Authorization: a user limited to s3:GetObject reads and cannot write.
echo "== Authorization =="
echo "hello" >"$WORK/object.txt"
expect_ok "root: s3 put object" \
    aws_as "$ROOT_KEY" "$ROOT_SECRET" s3api put-object --bucket smoke-bucket --key k --body "$WORK/object.txt"
expect_ok "root: iam create user" aws_as "$ROOT_KEY" "$ROOT_SECRET" iam create-user --user-name reader
expect_ok "root: iam put user policy" aws_as "$ROOT_KEY" "$ROOT_SECRET" iam put-user-policy \
    --user-name reader --policy-name read-only --policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::smoke-bucket/*"}]}'

READER="$(aws_as "$ROOT_KEY" "$ROOT_SECRET" iam create-access-key --user-name reader \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text 2>"$WORK/err")" || READER=""
READER_KEY="$(echo "$READER" | awk '{print $1}')"
READER_SECRET="$(echo "$READER" | awk '{print $2}')"
if [ -z "$READER_KEY" ] || [ -z "$READER_SECRET" ]; then
    fail "root: iam create access key for the reader"
    sed 's/^/    /' "$WORK/err"
    finish
fi
SECRETS+=("$READER_SECRET")
pass "root: iam create access key for the reader"

expect_ok "reader: s3 get object is allowed" \
    aws_as "$READER_KEY" "$READER_SECRET" s3api get-object --bucket smoke-bucket --key k "$WORK/downloaded.txt"
expect_denied "reader: s3 put object is denied" \
    aws_as "$READER_KEY" "$READER_SECRET" s3api put-object --bucket smoke-bucket --key other --body "$WORK/object.txt"

# 4. Restart: same data volume, no new root, same credentials keep working.
echo "== Restart =="
docker restart "$NAME" >/dev/null
wait_ready || finish
ALL_LOGS="$(docker logs "$NAME" 2>&1)"
GENERATED_COUNT="$(grep -c 'Generated root credentials' <<<"$ALL_LOGS" || true)"
if [ "$GENERATED_COUNT" -eq 1 ]; then
    pass "no second root is generated after a restart"
else
    fail "expected 1 'Generated root credentials' line across both starts, found ${GENERATED_COUNT}"
fi
SECRET_COUNT="$(grep -c -F "$ROOT_SECRET" <<<"$ALL_LOGS" || true)"
if [ "$SECRET_COUNT" -eq 1 ]; then
    pass "the root secret appears in the log exactly once"
else
    fail "the root secret appears ${SECRET_COUNT} times in the log, expected 1"
fi
expect_ok "root still works after the restart" aws_as "$ROOT_KEY" "$ROOT_SECRET" sts get-caller-identity
expect_ok "reader still reads after the restart" \
    aws_as "$READER_KEY" "$READER_SECRET" s3api get-object --bucket smoke-bucket --key k "$WORK/downloaded2.txt"
expect_denied "test/test is still rejected after the restart" aws_as test test sts get-caller-identity

# 5. Root from the environment replaces the stored one (same data volume).
echo "== Root from the environment =="
ENV_KEY="AKIAZZZZZZZZZZZZZZZZ"
ENV_SECRET="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
SECRETS+=("$ENV_SECRET")
start_container -e "FLOCI_ROOT_ACCESS_KEY_ID=${ENV_KEY}" -e "FLOCI_ROOT_SECRET_ACCESS_KEY=${ENV_SECRET}"
wait_ready || finish
expect_ok "the root from the environment works" aws_as "$ENV_KEY" "$ENV_SECRET" sts get-caller-identity
expect_denied "the previously stored root is replaced and rejected" \
    aws_as "$ROOT_KEY" "$ROOT_SECRET" sts get-caller-identity
ENV_LOGS="$(docker logs "$NAME" 2>&1)"
if grep -q -F "$ENV_SECRET" <<<"$ENV_LOGS"; then
    fail "the root secret passed by environment appears in the log"
else
    pass "the root secret passed by environment is not logged"
fi
if grep -q 'Generated root credentials' <<<"$ENV_LOGS"; then
    fail "a root was generated although one was passed by environment"
else
    pass "no root is generated when one is passed by environment"
fi

finish
