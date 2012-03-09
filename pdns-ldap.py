#!/usr/bin/python2 -u

# XXX: This is a toy, actually.
# External dependencies: ipaddr, python-ldap

from sys import stdin, stdout, exit
from time import strftime

from ldap.ldapobject import ReconnectLDAPObject
from ldap.dn import escape_dn_chars
from ipaddr import IPv4Address, IPv4Network, IPAddress

import ldap
import config

class DNSError(Exception):
    pass

def in_campus_factory():
    predicates = map(lambda x: IPv4Network(x).Contains, config.campus)
    def in_campus(ip):
        ip = IPv4Address(ip)
        for p in predicates:
            if p(ip):
                return True
        return False
    return in_campus

in_campus = in_campus_factory()

def make_answer(qname, qtype, content, qclass='IN', ttl=config.ttl, id_='-1'):
    return (qname, qclass, qtype, ttl, id_, content)

def compose_soa(zone):
    serial = strftime('%Y%m%d%H')
    ttl = config.ttl
    # XXX Hard-coded
    #      primary    hostmaster     serial          retry     ttl
    #                                           refresh  expire
    fmt = "dns.%(zone)s dns@%(zone)s %(serial)s 1200 600 28800 %(ttl)s";
    return fmt % locals()

def query_a(qtype, remote, tag, base):
    scope = ldap.SCOPE_BASE
    ipattr = 'ipHostNumber'

    try:
        re = connection.search_s(base, scope, attrlist=[ipattr])
    except ldap.NO_SUCH_OBJECT:
        return []

    # re looks like [ (dn, attr_dict), ... ]
    ips = re[0][1][ipattr]

    def is_v4(x):
        return IPAddress(x).version == 4
    def is_v6(x):
        return IPAddress(x).version == 6
    def geo_filter(ips, remote):
        filtered = [ x for x in ips if in_campus(x) == in_campus(remote) ]
        return filtered or ips

    results = []
    if qtype in ('AAAA', 'ANY') and tag != '4':
        li = filter(is_v6, ips)
        results.extend(zip(li, [ 'AAAA' ] * len(li)))
    if qtype in ('A', 'ANY') and tag != '6':
        li = geo_filter(filter(is_v4, ips), remote)
        results.extend(zip(li, [ 'A' ] * len(li)))
    return results

def query(qname, qclass, qtype, id_, remote):
    qname = qname.lower()
    if qclass != 'IN':
        raise DNSError('Unsupported qclass: %s (expceted "IN")' % qclass)
    tag = ''
    for zone in config.zones:
        if qname == zone:
            rqname = '@'
            break
        elif qname.endswith('.' + zone):
            rqname = qname[:-len('.' + zone)]
            if rqname in '46':
                tag = rqname
                rqname = '@'
            elif rqname[-2:] in ('.4', '.6'):
                tag = rqname[-1]
                rqname = rqname[:-2]
            break
    else:
        raise DNSError('Not in my zones: %s' % qname)

    answers = []

    if qtype in ('A', 'AAAA', 'ANY'):
        for fmt in config.searches:
            ips = query_a(qtype, remote, tag, fmt % (escape_dn_chars(rqname)))
            if ips:
                more = [ make_answer(qname, qtype_, ip)
                         for ip, qtype_ in ips ]
                answers.extend(more)
                break
    if qtype in ('NS', 'ANY'):
        if rqname == '@':
            more = [ make_answer(qname, 'NS', '%s.%s'%(dc, zone))
                     for dc in config.ns_dcs ]
            answers.extend(more)
    if qtype in ('SOA', 'ANY'):
        if rqname == '@':
            extra = make_answer(zone, 'SOA', compose_soa(zone))
            answers.append(extra)

    return answers

def output(*fields):
    stdout.write('\t'.join(fields))
    stdout.write('\n')
    stdout.flush()

def respond(fields):
    tag = fields.pop(0)
    if tag == 'PING':
        output('LOG', 'Ready.')
        return True
    elif tag == 'AXFR':
        return False
    elif tag == 'Q':
        try:
            answers = query(*fields)
            for answer in answers:
                output('DATA', *answer)
            return True
        except DNSError as e:
            output('LOG', 'DNS error: %s' % e)
            return False

def main():
    # Skip handshake when testing manually
    if not stdin.isatty():
        if stdin.readline() == 'HELO\t1\n':
            output('OK', 'pdns-ldap-py is ready')
        else:
            output('FAIL')
            stdin.readline()
            exit(1)

    # XXX Global variable
    global connection
    connection = ReconnectLDAPObject(config.uri)
    # XXX A little ugly here
    connection.deref = ldap.DEREF_FINDING

    if config.start_tls:
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, config.ca_cert)
        ldap.set_option(ldap.OPT_X_TLS_CERTFILE, config.cert)
        connection.start_tls_s()

    connection.bind(config.binddn, config.bindpw)

    while True:
        line = stdin.readline()
        if len(line) == 0:
            break
        fields = line.rstrip('\n').split('\t')
        if respond(fields):
            output('END')
        else:
            output('FAIL')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        output('LOG', 'Interrupted by user when in non-daemon mode')

