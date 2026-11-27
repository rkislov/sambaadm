# Kea GSS-TSIG / Samba AD integration

These drivers modify disposable laboratory containers. The AD fixture uses the
public test password from `testdata/samba`; no production credentials are needed.

The verified run used aarch64 ALT p10 (Kea 2.6.0) and p11 (Kea 3.2.0), with a
Samba 4.17 AD controller and BIND 9.18 DLZ. Systemd is not PID 1 in these containers.
Persistent service startup is not covered by this run; generated units were
checked with `systemd-analyze verify --man=no` on p11.

Expected lab inventory:

- `sambaadm-gss-ad-p11`: ALT p11 with Kea/D2 and native `kea-gss-tsig`.
- `sambaadm-gss-build-p10`: ALT p10 with Kea 2.6.0 and the RPM produced by the
  embedded worker (`install-plan`, then `install-job`). The complete worker build,
  RPM dependency verification and installation must finish with state `complete`.
- `sambaadm-gss-dc-test`: AD fixture built from `testdata/samba/Dockerfile`,
  realm `SAMBAADM.TEST`, DNS alias `dc1.sambaadm.test`, on the same Docker network.
  LDAPS presents `/var/lib/samba/private/tls/cert.pem`, copied as a trusted CA by
  the driver. Use `samba_upgradedns --dns-backend=BIND9_DLZ` on this fixture and
  start BIND with its generated DLZ include and `tkey-gssapi-keytab` setting.
  The driver uses BIND on port 1053, leaving the fixture's internal DNS on 53.

Create `sambaadm.test`, `0.0.10.in-addr.arpa` and
`0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa` before starting BIND. BIND must be
restarted after adding AD DNS zones so DLZ loads its zone inventory.

Run from the repository root:

```sh
python3 testdata/kea/gss/native-ad.py
```

The driver verifies stale-plan rejection, missing-zone rejection, AES keytab
permissions, signed A/AAAA/PTR creation and deletion, reuse without password
rotation, shared HA identity enrollment, partner deletion, and refusal to delete
an administrator-owned DNS record. The last run rotates only lab-managed
accounts so it can be repeated after a partial failure.

Then copy `d2-probe.py` into each ALT container and execute it with `GSS_DNS_IP`
set to the DC's IP. Optionally set `GSS_DNS_PORT` (default 1053) and
`GSS_TEST_OCTET` (choose an unused address in 10.0.0.0/24). This starts real D2
as `_kea`, loads the installed hook, submits real NCR wire messages, and checks
signed A/AAAA/PTR creation/deletion through DNS. It uses the shared identity's
cache after simulating the production service's `kinit -k` pre-start command.

`TestKeaRealGSSPlan` in `internal/service/kea_gss_integration_test.go` runs with
`SAMBAADM_KEA_GSS_TEST=1` and `GSS_DNS_IP` in the same containers. It checks the
actual helper-generated D2/DHCPv4/DHCPv6 configurations with native binaries,
credentials-cache use, AD conflict mode, and rejection of a mismatched principal.

Protocol, RBAC, CSRF and shared-secret response isolation tests run with
`go test ./...`. The browser regression is `testdata/web/kea.cjs` (Playwright).

An internal-DNS-only Samba 4.17 negative run returned invalid GSS response
signatures. The worker must fail that check; do not suppress signature errors
or substitute unsigned updates to make the test pass.
