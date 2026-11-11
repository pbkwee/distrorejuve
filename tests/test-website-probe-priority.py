#!/usr/bin/env python3
"""Synthetic primary/alias probe ordering; no external DNS, HTTP or services."""
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE=(Path(__file__).resolve().parents[1]/'distrorejuve.sh').read_text()
NAMES=['manifest_website_probe_authority','manifest_website_probe_network','manifest_website_queue_finish',
       'manifest_website','manifest_dns','manifest_http']


def declarations(names):
    parts=[]
    for name in names:
        found=re.search(r'^function '+re.escape(name)+r'\(\) \{\n.*?^\}',SOURCE,re.M|re.S)
        assert found,name
        parts.append(found[0])
    return '\n'.join(parts)


class WebsiteProbePriority(unittest.TestCase):
    def collect(self,body,setup='',extra=(),files=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for path,content in (files or {}).items():
                target=root/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);target.write_text(content)
            # A wildcard hostname must not expand to this local file.
            (root/'accidental.example.invalid').touch()
            script=declarations(NAMES+list(extra))+f'''
manifest_root={str(root)!r}
fixture_trace={str(root/'network.tsv')!r}
: > "$fixture_trace"
manifest_format=text
manifest_website_queue_active=true
manifest_website_queue=()
manifest_dns_enabled=true
manifest_dns_limit=20
manifest_dns_names=(); manifest_dns_values=(); manifest_dns_results=(); manifest_dns_reasons=()
manifest_http_enabled=true
manifest_http_seen=''
manifest_http_count=0
manifest_http_started=$SECONDS
manifest_local_addresses='192.0.2.10'
manifest_unprivileged=false
manifest_apache_php_available=false
manifest_fpm_sockets=(); manifest_fpm_users=(); manifest_fpm_versions=(); manifest_fpm_packages=()
manifest_seen_roots=''
manifest_web_started=$SECONDS
fixture_dns=true; fixture_timeout=true; fixture_curl=true; fixture_legacy_curl=false
manifest_emit() {{ printf '%s\\n' "$*"; }}
manifest_application() {{ printf 'application-metadata %s\\n' "$1"; }}
manifest_web_indicators() {{ printf 'file-metadata %s\\n' "$1"; }}
command() {{
  if [ "$1" = -v ]; then
    case "$2" in getent) "$fixture_dns";; host|perl) return 1;; timeout) "$fixture_timeout";; curl) "$fixture_curl";; *) builtin command "$@";; esac
  else builtin command "$@"; fi
}}
manifest_run_bounded() {{
  shift
  case "$1" in
    getent) printf 'dns\\t%s\\n' "$3" >> "$fixture_trace"; printf '192.0.2.10 STREAM example.invalid\\n';;
    curl)
      fixture_url="${{@: -1}}"
      if [ "$fixture_url" = --version ]; then
        printf 'capability\\t%s\\n' "$*" >> "$fixture_trace"
        if "$fixture_legacy_curl"; then return 2; fi
        return 0
      fi
      printf 'http\\t%s\\n' "$fixture_url" >> "$fixture_trace"
      case "$fixture_url" in https://streamproxy.example.invalid:443/)
        printf '000||60\\n'; return 60;;
        *) printf '200|192.0.2.10|0\\n';;
      esac;;
    *) "$@";;
  esac
}}
{setup}
{body}
printf '\\nTRACE-BEGIN\\n'
cat "$fixture_trace"
printf 'COUNTS %s %s\\n' "${{#manifest_dns_names[@]}}" "$manifest_http_count"
'''
            result=subprocess.run(['bash'],input=script,text=True,capture_output=True,cwd=root,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        output,trace=result.stdout.split('TRACE-BEGIN\n')
        events=[tuple(line.split('\t',1)) for line in trace.splitlines() if '\t' in line]
        counts=tuple(map(int,re.search(r'COUNTS (\d+) (\d+)',trace).groups()))
        capabilities = [value for kind, value in events if kind == 'capability']
        self.assertLessEqual(len(capabilities), 1)
        if capabilities:
            self.assertIn('--noproxy *', capabilities[0])
            self.assertIn('--proto =http,https', capabilities[0])
        return output, [event for event in events if event[0] != 'capability'], counts

    def test_legacy_curl_leaves_each_http_probe_unknown(self):
        output, events, counts = self.collect(
            'manifest_http one.example.invalid http 80\n'
            'manifest_http two.example.invalid https 443\n'
            'printf "incomplete=%s\\n" "$manifest_http_incomplete"',
            setup='fixture_legacy_curl=true')
        self.assertEqual(counts, (0, 0))
        self.assertEqual(events, [])
        self.assertEqual(output.count('reason curl_unsupported'), 2)
        self.assertIn('incomplete=true', output)

    def site(self,name,root,server='apache',port='80',tls='false',config='sites.conf',proxy='unknown'):
        return 'manifest_website '+ ' '.join(shlex.quote(s) for s in [server,name,str(port),tls,root,'www-data','unknown',config,'unknown',proxy])+'\n'

    def test_every_primary_precedes_aliases_within_existing_budgets(self):
        primary=['site'+str(i)+'.example.invalid' for i in range(1,8)]+['streamproxy.example.invalid']
        body=''
        for i,name in enumerate(primary):
            body+=self.site(','.join([name,'www.'+name,'webmail.'+name,'admin.'+name]),'/srv/site'+str(i),server=['apache','nginx','caddy','lighttpd'][i%4],proxy='127.0.0.1:8000' if i==7 else 'unknown')
        body+='printf "BEFORE-NETWORK\\n"\nmanifest_website_queue_finish\n'
        output,events,counts=self.collect(body)
        dns=[name for kind,name in events if kind=='dns']
        http=[url for kind,url in events if kind=='http']
        self.assertEqual(dns[:8],primary)
        self.assertEqual(len(http),40)
        self.assertEqual(counts,(20,40))
        self.assertEqual([url.split('://')[1].split(':')[0] for url in http[:16:2]],primary)
        self.assertIn('name streamproxy.example.invalid protocol https port 443',output)
        self.assertIn('tls_verify_result 60 curl_status 60 reason curl_error',output)
        self.assertIn('dns unknown dns_addresses unknown dns_reason domain_limit',output)
        self.assertIn('reason probe_limit',output)
        before=output.split('BEFORE-NETWORK')[0]
        self.assertEqual(before.count('application-metadata'),8)
        self.assertNotIn('website_probe',before)

    def test_generated_first_alias_does_not_hide_configured_primary(self):
        body=self.site('www.example.invalid,webmail.example.invalid,example.invalid,admin.example.invalid','/srv/site')+'manifest_website_queue_finish\n'
        _,events,_=self.collect(body)
        self.assertEqual([name for kind,name in events if kind=='dns'][0],'example.invalid')

    def test_generated_only_early_mappings_follow_later_main_representatives(self):
        body=''
        for number in range(24):
            label='webmail' if number%2 else 'admin'
            body+=self.site(label+'.early'+str(number)+'.example.invalid','/srv/generated'+str(number))
        primary=['main'+str(number)+'.example.invalid' for number in range(7)]+['streamproxy.example.invalid']
        for number,name in enumerate(primary):
            body+=self.site(name,'/srv/main'+str(number))
        body+='manifest_website_queue_finish\n'
        output,events,counts=self.collect(body)
        self.assertEqual([name for kind,name in events if kind=='dns'][:8],primary)
        self.assertEqual([url.split('://')[1].split(':')[0] for kind,url in events if kind=='http'][:16:2],primary)
        self.assertEqual(counts,(20,40))
        self.assertIn('name streamproxy.example.invalid protocol https port 443',output)
        self.assertIn('tls_verify_result 60 curl_status 60 reason curl_error',output)
        self.assertIn('website server apache name admin.early0.example.invalid',output)

    def test_generated_prefix_ranking_is_case_insensitive_only(self):
        body=self.site('WWW.Example.invalid,Webmail.Example.invalid,primary.example.invalid,Admin.Example.invalid','/srv/site')+'manifest_website_queue_finish\n'
        output,events,_=self.collect(body)
        self.assertEqual([name for kind,name in events if kind=='dns'][0],'primary.example.invalid')
        self.assertIn('name WWW.Example.invalid',output)
        self.assertTrue(any(kind=='dns' and name=='WWW.Example.invalid' for kind,name in events))

    def test_www_only_does_not_invent_unconfigured_apex(self):
        _,events,_=self.collect(self.site('www.example.invalid','/srv/site')+'manifest_website_queue_finish\n')
        self.assertEqual([name for kind,name in events if kind=='dns'],['www.example.invalid'])

    def test_distinct_vhosts_with_shared_root_remain_primary_groups(self):
        body=self.site('first.example.invalid,www.first.example.invalid','/srv/shared',config='one.conf')
        body+=self.site('second.example.invalid,www.second.example.invalid','/srv/shared',config='two.conf')+'manifest_website_queue_finish\n'
        output,events,_=self.collect(body)
        self.assertEqual([name for kind,name in events if kind=='dns'][:2],['first.example.invalid','second.example.invalid'])
        self.assertIn('config one.conf',output);self.assertIn('config two.conf',output)

    def test_duplicate_authorities_reuse_network_but_preserve_records(self):
        body=self.site('example.invalid,www.example.invalid','/srv/first',config='one.conf')
        body+=self.site('example.invalid,www.example.invalid','/srv/second',port=443,tls='true',config='two.conf')+'manifest_website_queue_finish\n'
        output,events,counts=self.collect(body)
        self.assertEqual(counts,(2,4))
        self.assertEqual(output.count('website server apache name example.invalid '),2)
        self.assertIn('document_root /srv/first',output);self.assertIn('document_root /srv/second',output)
        self.assertEqual(sum(event==('http','https://example.invalid:443/') for event in events),1)

    def test_unknown_scheme_tries_both_at_the_actual_port(self):
        body=self.site('example.invalid','/srv/site',port=8443,tls='unknown')+'manifest_website_queue_finish\n'
        output,events,_=self.collect(body)
        self.assertEqual([url for kind,url in events if kind=='http'],['http://example.invalid:8443/','https://example.invalid:8443/'])
        self.assertIn('url unknown primary_url unknown',output)

    def test_alias_port_override_does_not_leak_to_next_name(self):
        body=self.site('explicit.example.invalid:8080,inherited.example.invalid','/srv/site',port=8443,tls='true')+'manifest_website_queue_finish\n'
        output,events,_=self.collect(body)
        self.assertEqual([url for kind,url in events if kind=='http'],['https://explicit.example.invalid:8080/','https://inherited.example.invalid:8443/'])
        self.assertIn('name inherited.example.invalid port 8443',output)

    def test_missing_clients_leave_explicit_unknown_records(self):
        output,events,_=self.collect(self.site('example.invalid','/srv/site')+'manifest_website_queue_finish\n',setup='fixture_dns=false; fixture_curl=false')
        self.assertEqual(events,[])
        self.assertIn('dns_reason resolver_client_unavailable',output)
        self.assertIn('reason curl_unavailable',output)

    def test_missing_timeout_facility_does_not_run_dns(self):
        output,events,_=self.collect(self.site('example.invalid','/srv/site')+'manifest_website_queue_finish\n',setup='fixture_timeout=false; fixture_curl=false')
        self.assertEqual(events,[])
        self.assertIn('dns_reason timeout_facility_unavailable',output)

    def test_unprivileged_and_disabled_http_keep_skip_reasons(self):
        for setup,reason in [('manifest_unprivileged=true','skipped_unprivileged'),('manifest_http_enabled=false','disabled')]:
            with self.subTest(reason=reason):
                output,events,_=self.collect(self.site('example.invalid','/srv/site')+'manifest_website_queue_finish\n',setup=setup)
                self.assertFalse(any(kind=='http' for kind,_ in events))
                self.assertIn('reason '+reason,output)

    def test_expired_http_budget_never_consumes_file_metadata_budget(self):
        setup='''
'''
        # Use the original bounded probe with an already-expired clock; no real wait.
        original=declarations(['manifest_http']).replace('function manifest_http()', 'function fixture_manifest_http()')
        setup+=original+'''\nmanifest_http() { manifest_http_started=$((SECONDS-45)); fixture_manifest_http "$@"; }\n'''
        output,events,_=self.collect(self.site('example.invalid','/srv/site')+'manifest_website_queue_finish\nprintf "FILE-BUDGET %s\\n" "$((SECONDS-manifest_web_started))"\n',setup=setup)
        self.assertFalse(any(kind=='http' for kind,_ in events))
        self.assertIn('reason probe_limit',output)
        self.assertIn('application-metadata /srv/site',output)
        self.assertLessEqual(int(re.search(r'FILE-BUDGET ([0-9]+)',output).group(1)),1)

    def test_wildcards_do_not_expand_to_local_files(self):
        output,events,_=self.collect(self.site('*.example.invalid','/srv/site')+'manifest_website_queue_finish\n')
        self.assertEqual(events,[])
        self.assertIn('name *.example.invalid',output)
        self.assertIn('dns_reason wildcard_or_dynamic_name',output)

    def test_queue_overflow_keeps_metadata_without_network_requests(self):
        setup='for ((i=0;i<6144;i++)); do manifest_website_queue[i]=unknown; done'
        output,events,_=self.collect(self.site('example.invalid','/srv/site'),setup=setup)
        self.assertEqual(events,[])
        self.assertIn('website server apache name example.invalid',output)
        self.assertIn('dns_reason priority_queue_limit',output)
        self.assertIn('reason priority_queue_limit',output)
        self.assertIn('application-metadata /srv/site',output)

    def test_space_containing_paths_and_invalid_queue_delimiters(self):
        body=self.site('example.invalid','/srv/site with spaces')+'manifest_website_queue_finish\n'
        output,_,_=self.collect(body,files={'/srv/site with spaces/index.html':'fixture'})
        self.assertIn('document_root /srv/site with spaces document_root_exists true',output)
        output,events,_=self.collect(self.site('other.example.invalid','/srv/site\tbad'))
        self.assertEqual(events,[])
        self.assertIn('dns_reason priority_queue_limit',output)

    def test_all_standard_server_paths_enqueue_before_any_network(self):
        files={
            '/apache.conf':'<VirtualHost *:80>\nServerName apache.example.invalid\nServerAlias www.apache.example.invalid webmail.apache.example.invalid admin.apache.example.invalid\nDocumentRoot /srv/apache\n</VirtualHost>\n',
            '/nginx.conf':'server {\nlisten 80;\nserver_name nginx.example.invalid www.nginx.example.invalid webmail.nginx.example.invalid admin.nginx.example.invalid;\nroot /srv/nginx;\n}\n',
            '/Caddyfile':'caddy.example.invalid, www.caddy.example.invalid, webmail.caddy.example.invalid, admin.caddy.example.invalid {\nroot * /srv/caddy\n}\n',
            '/etc/lighttpd/lighttpd.conf':'fixture present; parser output is mocked\n',
        }
        setup='''
manifest_read_metadata() { head -c 1048576 -- "$1"; }
manifest_config_files() { case "$1" in apache) printf '%s/apache.conf\\n' "$manifest_root";; nginx) printf '%s/nginx.conf\\n' "$manifest_root";; caddy) printf '%s/Caddyfile\\n' "$manifest_root";; esac; }
manifest_lighttpd_frontends() { :; }
manifest_lighttpd_handler() { :; }
manifest_website_assets() { :; }
manifest_lighttpd_output_configuration() { printf 'site\\t1\\tstreamproxy.example.invalid\\tliteral_host\\t80\\tfalse\\t/srv/audio\\twww-data\\treverse_proxy\\t/etc/lighttpd/lighttpd.conf\\t1\\tunknown\\tcomplete\\n'; }
'''
        body='manifest_websites\n[ ! -s "$fixture_trace" ] || exit 97\nmanifest_website_queue_finish\n'
        output,events,_=self.collect(body,setup=setup,extra=('manifest_websites','manifest_lighttpd_websites'),files=files)
        self.assertEqual([name for kind,name in events if kind=='dns'][:4],['apache.example.invalid','nginx.example.invalid','caddy.example.invalid','streamproxy.example.invalid'])
        for server in ('apache','nginx','caddy','lighttpd'): self.assertIn('website server '+server,output)


if __name__=='__main__': unittest.main()
