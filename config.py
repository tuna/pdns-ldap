uri = 'ldap://ldap2.tuna.tsinghua.edu.cn'
start_tls = True
ca_cert = '/etc/ssl/tuna/ca.crt'
cert = '/etc/ssl/tuna/server.crt'

binddn = 'cn=pdns,ou=robots,o=tuna'
bindpw = "NOT STORED IN GIT REPO"

ttl = '300'
zones = ( 'tuna.tsinghua.edu.cn', 'tuna' )
ns_dcs = ( 'dns', 'dns2' )
campus = ( '59.66.0.0/16', '166.111.0.0/16' )

searches = ( 'cn=%s,ou=services,o=tuna', 'cn=%s,ou=hosts,o=tuna' )

