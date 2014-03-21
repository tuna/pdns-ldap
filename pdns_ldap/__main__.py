# NOTE: This is a toy, actually.
# External dependencies: ipaddr, python-ldap

import traceback

from sys import stdin, stdout, exit
from time import strftime
from collections import Iterable

from ldap.ldapobject import ReconnectLDAPObject
from ldap.dn import escape_dn_chars
from ipaddr import IPv4Address, IPv4Network, IPAddress

import ldap
import config


class Domain(object):
    def __init__(self, value):
        if isinstance(value, basestring):
            self._parts = value.split('.') if value else []
        elif isinstance(value, Iterable):
            self._parts = value
        else:
            raise TypeError('value must be basestring or other iterable type')

    def __getitem__(self, k):
        return self._parts[k]

    def __setitem__(self, k, v):
        self._parts[k] = v

    def __len__(self):
        return len(self._parts)

    def __getslice__(self, i, j):
        return Domain(self._parts[i:j])

    def __eq__(self, rhs):
        return type(self) == type(rhs) and self._parts == rhs._parts

    def __str__(self):
        return '.'.join(self._parts)

    def __repr__(self):
        return 'Domain(%r)' % str(self)

    def __le__(self, rhs):
        '''Returns true if lhs is a subdomain of rhs.'''
        if not isinstance(rhs, Domain):
            raise TypeError('Both operands should be of Domain type')
        return len(rhs) == 0 or self[-len(rhs):] == rhs

    def pop(self):
        return self._parts.pop()

    def appendleft(self, v):
        return self._parts.insert(0, v)


class DNSError(Exception):
    pass


def _in_campus_factory():
    predicates = map(lambda x: IPv4Network(x).Contains, config.campus)

    def in_campus(ip):
        ip = IPv4Address(ip)
        for p in predicates:
            if p(ip):
                return True
        return False
    return in_campus

in_campus = _in_campus_factory()


def make_answer(qname, qtype, content, qclass='IN', ttl=config.ttl, id_='-1'):
    return (qname, qclass, qtype, ttl, id_, content)


def compose_soa(zone):
    serial = strftime('%Y%m%d%H')
    ttl = config.ttl
    # XXX Hard-coded
    #      primary    hostmaster     serial          retry     ttl
    #                                           refresh  expire
    fmt = "dns.%(zone)s dns@%(zone)s %(serial)s 1200 600 28800 %(ttl)s"
    return fmt % locals()

connection = None

known_tags = list('46io')


def query_a(qtype, remote, tags, base):
    scope = ldap.SCOPE_BASE
    ipattr = 'ipHostNumber'

    try:
        re = connection.search_s(base, scope, attrlist=[ipattr])
    except ldap.LDAPError as e:
        if not isinstance(e, ldap.NO_SUCH_OBJECT):
            output('LOG', 'Unusual LDAP exception: %s' % e)
            output('LOG', 'Base was: %s' % base)
        return []

    # re looks like [ (dn, attr_dict), ... ]
    ips = re[0][1][ipattr]

    def is_v4(x):
        return IPAddress(x).version == 4

    def is_v6(x):
        return IPAddress(x).version == 6

    def geo_filter(ips, in_):
        filtered = [x for x in ips if in_campus(x) == in_]
        return filtered or ips

    results = []
    if qtype in ('AAAA', 'ANY') and '4' not in tags:
        li = filter(is_v6, ips)
        results.extend(zip(li, ['AAAA'] * len(li)))
    if qtype in ('A', 'ANY') and '6' not in tags:
        if 'i' in tags:
            in_ = True
        elif 'o' in tags:
            in_ = False
        else:
            in_ = in_campus(remote)
        li = geo_filter(filter(is_v4, ips), in_)
        results.extend(zip(li, ['A'] * len(li)))
    return results


def query(qname, qclass, qtype, id_, remote):
    if qclass != 'IN':
        raise DNSError('Unsupported qclass: %s (expceted "IN")' % qclass)
    domain = Domain(qname.lower())

    tags = set()
    if not hasattr(config, '_zone_domains'):
        config._zone_domains = [Domain(z) for z in config.zones]
    for zone in config._zone_domains:
        if domain <= zone:
            relative = domain[:-len(zone)]
            while relative and relative[-1] in known_tags:
                tags.add(relative.pop())
            break
    else:
        raise DNSError('Not in my zones: %s' % qname)

    answers = []

    if qtype in ('A', 'AAAA', 'ANY'):

        def do_query_a(name):
            return query_a(qtype, remote, tags, fmt % escape_dn_chars(name))

        for fmt in config.searches:
            ips = do_query_a(str(relative) or '@')
            if not ips and len(relative) > 0:
                # Wildcard support.
                # Currently only cn=**.<dc> elements in the LDAP tree are
                # respected. <dc> is a single domain component, and the **
                # matches an arbitrary number of domain components.
                wild_relative = relative[-1:]
                wild_relative.appendleft('**')
                ips = do_query_a(str(wild_relative))
            if ips:
                more = [make_answer(qname, qtype_, ip) for ip, qtype_ in ips]
                answers.extend(more)
                break

    if len(relative) == 0 or \
            relative == Domain('v') and qtype in ('MX', 'ANY'):
            # Live with this awkward hack until the big LDAP tree restructure
        for qt, data in config.root_specials.items():
            if qtype in (qt, 'ANY'):
                more = [make_answer(qname, qt, '%s.%s' % (datum, zone))
                        for datum in data]
                answers.extend(more)

        if qtype in ('SOA', 'ANY'):
            extra = make_answer(qname, 'SOA', compose_soa(str(zone)))
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
    if stdin.isatty():
        print('stdin is tty, skipping handshake')
    else:
        if stdin.readline() == 'HELO\t1\n':
            output('OK', 'pdns-ldap-py is ready')
        else:
            output('FAIL')
            stdin.readline()
            exit(1)

    # XXX Global variable
    global connection
    connection = ReconnectLDAPObject(config.uri, retry_max=4, retry_delay=5)
    # XXX A little ugly here
    connection.deref = ldap.DEREF_FINDING

    if config.start_tls:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        connection.start_tls_s()

    connection.bind_s(config.binddn, config.bindpw)

    while True:
        line = stdin.readline()
        if len(line) == 0:
            continue
        fields = line.rstrip('\n').split('\t')
        try:
            if respond(fields):
                output('END')
            else:
                output('FAIL')
        except Exception:
            output('FAIL')
            output('LOG', 'Unexpected error, traceback:')
            tb_lines = traceback.format_exc().split('\n')
            for line in tb_lines:
                output('LOG', line)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        output('LOG', 'Interrupted by user when in non-daemon mode')
