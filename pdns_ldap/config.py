from socket import gethostname
# XXX Quick-and-dirty way of adapting configuration
hostname = gethostname()
if hostname == 'BigEagle-desktop':
    uri = 'ldap://ldap.tuna.tsinghua.edu.cn'
    start_tls = True
elif hostname.startswith('alef'):
    uri = 'ldap://ldap2.tuna.tsinghua.edu.cn'
    start_tls = True
elif hostname.startswith('major'):
    uri = 'ldap://127.0.0.1'
    start_tls = False
else:
    raise Exception('Unknown host: %s. Cannot determine profile' % hostname)

ca_cert = '/etc/ssl/tuna/ca.crt'
cert = '/etc/ssl/tuna/server.crt'

binddn = 'cn=pdns,ou=robots,o=tuna'
bindpw = "NOT STORED IN GIT REPO"

ttl = '512'
zones = ['tuna.tsinghua.edu.cn', 'tuna', 'tuna.edu.cn']
edu_zones = ["mirrors.edu.cn", "mirror.edu.cn", 'mirrors.tsinghua.edu.cn']

root_specials = {
    'NS': ['dns.%(zone)s', 'dns2.%(zone)s'],
    'MX': ['10\tms94010085.msv1.invalid.outlook.com'],
}

campus = ['59.66.0.0/16', '166.111.0.0/16']
campus6 = ['2402:F000::/32', ]

searches = ['cn=%s,ou=domains,o=tuna', 'cn=%s,ou=hosts,o=tuna']

raw_search = 'dc=%s,ou=domains,o=tuna'

edu_search = lambda domain: 'cn=%%s,ou=%s,ou=edu-domains,o=tuna' % domain
edu_raw_search = lambda domain: 'dc=%%s,ou=%s,ou=edu-domains,o=tuna' % domain


try:
    from config_local import *
except ImportError:
    pass

