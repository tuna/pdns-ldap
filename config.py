from socket import gethostname
# XXX Quick-and-dirty way of adapting configuration
hostname = gethostname()
if hostname == 'blackie':
    uri = 'ldap://ldap2.tuna.tsinghua.edu.cn'
    start_tls = True
elif hostname.startswith('alef'):
    uri = 'ldap://192.168.100.2'
    start_tls = False
elif hostname.startswith('major'):
    uri = 'ldap://127.0.0.1'
    start_tls = False
else:
    raise Exception('Unknown host: %s. Cannot determine profile' % hostname)

ca_cert = '/etc/ssl/tuna/ca.crt'
cert = '/etc/ssl/tuna/server.crt'

binddn = 'cn=pdns,ou=robots,o=tuna'
bindpw = "NOT STORED IN GIT REPO"

ttl = '60'
zones = ( 'tuna.tsinghua.edu.cn', 'tuna' )
ns_dcs = ( 'dns', 'dns2' )
campus = ( '59.66.0.0/16', '166.111.0.0/16' )

searches = ( 'cn=%s,ou=domains,o=tuna', 'cn=%s,ou=hosts,o=tuna' )

