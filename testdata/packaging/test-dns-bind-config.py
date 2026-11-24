#!/usr/bin/python3
import pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]/'internal/service'))
from helper_dns_bind_config import patch_bind_options,normalize_forwarders
before='''// options { fake; } in a comment
options {
 directory "/etc/bind/zone";
 listen-on port 53 { 127.0.0.1; };
 // quoted punctuation must not affect brace counting
 version "text; { }";
 include "/etc/bind/resolvconf-options.conf";
 allow-recursion { localhost; };
};
logging { channel audit { null; }; };
zone "manual.test" { type primary; file "manual.zone"; };
'''
values={'listen-on':'{ any; }','allow-recursion':'{ localhost; localnets; 10.10.0.0/16; }','tkey-gssapi-keytab':'"/var/lib/samba/bind-dns/dns.keytab"'}
after=patch_bind_options(before,values,remove_resolvconf=True)
for keep in ['directory "/etc/bind/zone";','version "text; { }";','logging { channel audit { null; }; };','zone "manual.test" { type primary; file "manual.zone"; };']:
 assert keep in after,after
assert after.count('listen-on ')==1 and '127.0.0.1;' not in after
assert 'resolvconf-options.conf' not in after
assert '10.10.0.0/16;' in after
assert 'resolvconf-options.conf' in patch_bind_options(before,{'minimal-responses':'yes'})
for invalid in ['options { listen-on { any; };','options {}; options {};','zone "options" {type primary;};']:
 try:patch_bind_options(invalid,values)
 except ValueError:pass
 else:raise AssertionError('ambiguous BIND configuration accepted: '+invalid)
assert normalize_forwarders(['10.10.1.14'])==['10.10.1.14']
assert normalize_forwarders('10.10.1.14 127.0.0.1')==['10.10.1.14']
print('PASS ALT BIND patch: safe braces/comments/strings, preserve unrelated settings, reject ambiguous config')
