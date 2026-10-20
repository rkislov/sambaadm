#!/bin/sh
# Run only against a disposable domain owned by this invocation.
set -eu
cd "$(dirname "$0")/../.."
project="sambaadm-it-$$"
work=$(mktemp -d)
compose() {
 if [ "${SAMBAADM_TWO_DC:-0}" = 1 ]; then
  docker compose -p "$project" -f testdata/docker-compose.yml -f testdata/docker-compose.two-dc.yml "$@"
 else
  docker compose -p "$project" -f testdata/docker-compose.yml "$@"
 fi
}
cleanup() {
    result=$?
    trap - EXIT
    if [ "$result" -ne 0 ]; then compose logs --tail=100 || true; fi
    compose down --volumes >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
if [ "${SAMBAADM_TWO_DC:-0}" = 1 ]; then SAMBAADM_IT_SECOND_DC=dc2.sambaadm.test; export SAMBAADM_IT_SECOND_DC; fi
compose up -d --build --wait --wait-timeout 240
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
for package in service web; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$work/$package.test" "./internal/$package"
    compose cp "$work/$package.test" "dc:/tmp/$package.test"
    compose exec -T -e SAMBAADM_IT=1 -e SAMBAADM_IT_MUTATE=SAMBAADM.TEST \
        -e SAMBAADM_IT_URI=ldaps://127.0.0.1:636 \
        -e SAMBAADM_IT_USER=Administrator@sambaadm.test -e SAMBAADM_IT_SECOND_DC="${SAMBAADM_IT_SECOND_DC:-}" dc \
        sh -c 'export SAMBAADM_PASSWORD="$SAMBAADM_LAB_PASSWORD"; exec "/tmp/$1.test" -test.run Integration -test.v -test.timeout 4m' sh "$package"
done
