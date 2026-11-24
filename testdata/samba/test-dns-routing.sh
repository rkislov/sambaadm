#!/bin/sh
# Disposable Samba/BIND with a private upstream. No host DNS ports are exposed.
set -eu
cd "$(dirname "$0")/../.."
name="sambaadm-dns-it-$$"
work=$(mktemp -d)
cleanup(){ docker rm -f "$name-upstream" "$name-dc" >/dev/null 2>&1 || true; docker network rm "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 130' INT TERM
docker build -q -t sambaadm-dns-it-base testdata/samba >/dev/null
docker build -q -f testdata/samba/Dockerfile.dns -t sambaadm-dns-it testdata/samba >/dev/null
arch=$(docker image inspect sambaadm-dns-it --format '{{.Architecture}}')
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$work/service.test" ./internal/service
docker run --rm --entrypoint python3 -v "$PWD:/src:ro" sambaadm-dns-it /src/testdata/packaging/test-dns-bind-config.py
docker run --rm --entrypoint python3 -v "$PWD:/src:ro" sambaadm-dns-it /src/testdata/packaging/test-dns-backend.py
docker network create "$name" >/dev/null
docker run -d --name "$name-upstream" --network "$name" --entrypoint python3 -v "$PWD:/src:ro" sambaadm-dns-it /src/testdata/samba/dns-upstream.py >/dev/null
upstream=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name-upstream")
docker run --rm --name "$name-dc" --network "$name" --hostname dc1 --entrypoint python3 -e SAMBAADM_DNS_UPSTREAM="$upstream" -v "$PWD:/src:ro" -v "$work/service.test:/service.test:ro" sambaadm-dns-it /src/testdata/samba/test-dns-backend-real.py
