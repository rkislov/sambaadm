#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
container="sambaadm-caja-qa-$$"
out=${1:-/tmp/sambaadm-caja-results}
work=$(mktemp -d)
mkdir -p "$out"
cleanup() {
 result=$?
 trap - EXIT
 docker cp "$container:/tmp/caja-artifacts/." "$out/" >/dev/null 2>&1 || true
 docker rm -f "$container" >/dev/null 2>&1 || true
 rm -rf "$work"
 exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
docker build -t sambaadm-caja-p11:local -f testdata/caja/Dockerfile testdata/caja
docker run -d --name "$container" --network none --shm-size=256m sambaadm-caja-p11:local sleep infinity >/dev/null
docker cp testdata/caja/setup.sh "$container:/tmp/caja-setup.sh"
docker cp testdata/caja/session.py "$container:/tmp/caja-session.py"
docker exec "$container" sh /tmp/caja-setup.sh
arch=$(docker inspect --format '{{.Image}}' "$container" | xargs docker image inspect --format '{{.Architecture}}')
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$work/service.test" ./internal/service
docker cp "$work/service.test" "$container:/tmp/sambaadm-service.test"
docker exec "$container" sh -c 'for i in $(seq 1 50); do DISPLAY=:99 xdotool getdisplaygeometry >/dev/null 2>&1 && exit 0; sleep .1; done; exit 1'
docker exec -d "$container" sh -c 'runuser -u cajaqa -- env DISPLAY=:99 XDG_RUNTIME_DIR=/tmp/caja-runtime LANG=C.UTF-8 NO_AT_BRIDGE=0 dbus-run-session -- python3 /tmp/caja-session.py > /tmp/caja-artifacts/session.log 2>&1; status=$?; echo "$status" > /tmp/caja-artifacts/session-exit'
# Wait for the UI's before phase, then apply the application's read/traverse template.
for i in $(seq 1 120); do
 if docker exec "$container" test -f /tmp/caja-artifacts/session-exit; then break; fi
 if docker exec "$container" test -f /tmp/caja-artifacts/needs-x; then
  docker exec -e SAMBAADM_IT_CAJA=1 "$container" /tmp/sambaadm-service.test -test.run '^TestIntegrationCajaDirectoryTemplate$' -test.v > "$work/template.log" 2>&1
  cat "$work/template.log"
  docker cp "$work/template.log" "$container:/tmp/caja-artifacts/template.log"
  docker exec "$container" sh -c 'getfacl -p -n /srv/sambaadm-caja-test/* > /tmp/caja-artifacts/after-acl.txt; touch /tmp/caja-artifacts/x-restored'
  break
 fi
 sleep 1
done
for i in $(seq 1 90); do
 if docker exec "$container" test -f /tmp/caja-artifacts/session-exit; then
  docker exec "$container" cat /tmp/caja-artifacts/versions.txt /tmp/caja-artifacts/session.log
  code=$(docker exec "$container" cat /tmp/caja-artifacts/session-exit)
  exit "$code"
 fi
 sleep 1
done
echo 'Caja session timed out' >&2
exit 1
