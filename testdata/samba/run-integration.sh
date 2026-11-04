#!/bin/sh
# Run only against a disposable domain owned by this invocation.
set -eu
cd "$(dirname "$0")/../.."
project="sambaadm-it-$$"
work=$(mktemp -d)
compose() {
 if [ "${SAMBAADM_RODC:-0}" = 1 ]; then
  docker compose -p "$project" -f testdata/docker-compose.yml -f testdata/docker-compose.rodc.yml "$@"
 elif [ "${SAMBAADM_TWO_DC:-0}" = 1 ]; then
  docker compose -p "$project" -f testdata/docker-compose.yml -f testdata/docker-compose.two-dc.yml "$@"
 else
  docker compose -p "$project" -f testdata/docker-compose.yml "$@"
 fi
}
cleanup() {
    result=$?
    trap - EXIT
    if [ "$result" -ne 0 ]; then
      if [ "${SAMBAADM_HELPERS:-0}" = 1 ]; then
        compose exec -T dc cat /tmp/helper-server.log || true
        compose exec -T dc2 cat /tmp/helper-server.log || true
        compose exec -T dc2 cat /tmp/helper-sshd.log || true
      fi
      compose logs --tail=100 || true
    fi
    compose down --volumes >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
if [ "${SAMBAADM_TWO_DC:-0}" = 1 ]; then SAMBAADM_IT_SECOND_DC=dc2.sambaadm.test; export SAMBAADM_IT_SECOND_DC; fi
compose up -d --build --wait --wait-timeout 240
if [ "${SAMBAADM_RODC:-0}" = 1 ]; then
 compose cp dc:/var/lib/samba/private/tls/cert.pem "$work/dc1.crt"
 compose cp "$work/dc1.crt" rodc:/usr/local/share/ca-certificates/dc1.crt
 compose exec -T rodc update-ca-certificates >/dev/null
fi
if [ "${SAMBAADM_TWO_DC:-0}" = 1 ]; then
 compose cp dc:/var/lib/samba/private/tls/cert.pem "$work/dc1.crt"
 compose cp dc2:/var/lib/samba/private/tls/cert.pem "$work/dc2.crt"
 compose cp "$work/dc2.crt" dc:/usr/local/share/ca-certificates/dc2.crt
 compose cp "$work/dc1.crt" dc2:/usr/local/share/ca-certificates/dc1.crt
 compose exec -T dc update-ca-certificates >/dev/null
 compose exec -T dc2 update-ca-certificates >/dev/null
fi

case "$(compose exec -T dc uname -m | tr -d '\r')" in
    aarch64) arch=arm64 ;;
    x86_64) arch=amd64 ;;
    *) echo 'Unsupported container architecture' >&2; exit 1 ;;
esac
if [ "${SAMBAADM_HELPERS:-0}" = 1 ]; then . ./testdata/samba/helper-setup.sh; fi
for package in service web; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$work/$package.test" "./internal/$package"
    compose cp "$work/$package.test" "dc:/tmp/$package.test"
    if [ "${SAMBAADM_RODC:-0}" != 1 ]; then
    compose exec -T -e SAMBAADM_IT=1 -e SAMBAADM_IT_MUTATE=SAMBAADM.TEST -e SAMBAADM_IT_TEST_PATTERN="${SAMBAADM_IT_TEST_PATTERN:-Integration}" \
        -e SAMBAADM_IT_URI=ldaps://127.0.0.1:636 \
        -e SAMBAADM_IT_USER=Administrator@sambaadm.test -e SAMBAADM_IT_SECOND_DC="${SAMBAADM_IT_SECOND_DC:-}" -e SAMBAADM_IT_HELPERS="${SAMBAADM_HELPERS:-0}" dc \
        sh -c 'export SAMBAADM_PASSWORD="$SAMBAADM_LAB_PASSWORD"; exec "/tmp/$1.test" -test.run "$SAMBAADM_IT_TEST_PATTERN" -test.v -test.timeout 4m' sh "$package"
    fi
done
if [ "${SAMBAADM_RODC:-0}" = 1 ]; then
 compose cp "$work/service.test" rodc:/tmp/service.test
 # Prove runtime preload uses native bindings, not the provisioning CLI.
 compose exec -T rodc mv /usr/bin/samba-tool /usr/bin/samba-tool.disabled
 compose exec -T -e SAMBAADM_IT=1 -e SAMBAADM_IT_MUTATE=SAMBAADM.TEST \
   -e SAMBAADM_IT_URI=ldaps://dc1.sambaadm.test:636 \
   -e SAMBAADM_IT_USER=Administrator@sambaadm.test -e SAMBAADM_IT_RODC=rodc.sambaadm.test rodc \
   sh -c 'export SAMBAADM_PASSWORD="$SAMBAADM_LAB_PASSWORD"; exec /tmp/service.test -test.run IntegrationRODC -test.v -test.timeout 4m'
fi
