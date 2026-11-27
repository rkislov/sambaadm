#!/bin/sh
# Actual AD join, SID/UID/GID, signed SMB and inherited ACL for both providers.
set -eu
cd "$(dirname "$0")/../.."
branch=${ALT_BRANCH:-p11}
case $branch in p10|p11) ;; *) echo "Use ALT_BRANCH=p10 or p11" >&2;exit 2;; esac
prefix=sambaadm-member-qa-$$
network=$prefix-net
dc=$prefix-dc
out=${1:-/tmp/sambaadm-member-results}
mkdir -p "$out"
cleanup() {
 result=$?
 trap - EXIT
 for name in "$prefix-winbind" "$prefix-sssd" "$dc"; do
  docker logs "$name" > "$out/${name##$prefix-}.container.log" 2>&1 || true
  docker rm -f "$name" >/dev/null 2>&1 || true
 done
 docker network rm "$network" >/dev/null 2>&1 || true
 exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
docker build --build-arg ALT_BRANCH="$branch" -t "sambaadm-member-$branch:local" -f testdata/member/Dockerfile testdata/member
docker build -t sambaadm-member-dc:local testdata/samba
docker network create "$network" >/dev/null
docker run -d --name "$dc" --hostname dc1 --network "$network" --network-alias dc1.sambaadm.test sambaadm-member-dc:local >/dev/null
dns=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$dc")
ready=false
for i in $(seq 1 90); do
 if docker exec "$dc" samba-tool user show Administrator >/dev/null 2>&1; then
  if docker exec "$dc" python3 -c 'import socket;socket.create_connection(("127.0.0.1",389),timeout=1).close();socket.create_connection(("127.0.0.1",88),timeout=1).close()' >/dev/null 2>&1; then ready=true;break;fi
 fi
 sleep 1
done
[ "$ready" = true ] || { echo 'DC did not start' >&2;exit 1; }
for profile in winbind sssd; do
 name=$prefix-$profile
 case $profile in winbind) hostname=fswb;; sssd) hostname=fsss;; esac
 docker run -d --name "$name" --hostname "$hostname.sambaadm.test" --network "$network" --network-alias "$hostname.sambaadm.test" --dns "$dns" --dns-search sambaadm.test "sambaadm-member-$branch:local" sleep infinity >/dev/null
 address=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
 docker cp internal/domaininit/member.py "$name:/tmp/member.py"
 docker cp testdata/member/check.py "$name:/tmp/check.py"
 docker exec -e PROFILE="$profile" -e ADDRESS="$address" -e DNS="$dns" "$name" python3 /tmp/check.py > "$out/$profile.log" 2>&1
 cat "$out/$profile.log"
done
echo "PASS both ALT $branch member profiles: AD join, matching NSS/Samba IDs, signed SMB write/read, file without x, inherited directory x."
