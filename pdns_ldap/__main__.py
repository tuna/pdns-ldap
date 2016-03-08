# NOTE: This is a toy, actually.
# External dependencies: ipaddr, python-ldap

import traceback

from sys import stdin, stdout, exit
from time import strftime
from collections import Iterable

from ldap.ldapobject import ReconnectLDAPObject
from ldap.dn import escape_dn_chars
from ipaddr import IPv4Address, IPv4Network, IPAddress, IPv6Network, IPv6Address

import ldap
import config


class Domain(object):
    """
    Domain represents a domain name. It can be created either from a list of
    domain parts or a string with an optional trailing dot:

    >>> Domain('tuna.moe')
    Domain('tuna.moe')
    >>> Domain(['tuna', 'moe'])
    Domain('tuna.moe')

    When indexed, it behaves like a list of domain parts. Slicing returns
    another Domain instance:

    >>> d = Domain('tuna.moe')
    >>> d[0]
    'tuna'
    >>> d[:1]
    Domain('tuna')

    Domains form a partially ordered set. Two instances are equally iff they
    represents the same domain name, and domain x is smaller than domain y iff
    x is a subdomain of y:

    >>> Domain('tuna.moe') == Domain(['tuna', 'moe'])
    True
    >>> Domain('blog.tuna.moe') < Domain('tuna.moe')
    True
    >>> Domain('a.tuna.moe') < Domain('b.tuna.moe')
    False
    >>> Domain('b.tuna.moe') < Domain('a.tuna.moe')
    False
    """
    def __init__(self, value):
        if isinstance(value, basestring):
            self._parts = [part for part in value.split('.') if part]
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

    def __lt__(self, rhs):
        return self <= rhs and self != rhs

    def pop(self):
        """
        Removes and returns the leftmost part. This produces the most specific
        part of the Domain and replaces the Domain with its parent domain.
        """
        return self._parts.pop()

    def appendleft(self, v):
        """
        Appends a new part to the left. This is useful for constructing a
        child domain.
        """
        return self._parts.insert(0, v)


class DNSError(Exception):
    """
    Indicates that the query cannot be answered.
    """


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
campus_accessible = in_campus

def _in_campus6_factory():
    predicates = map(lambda x: IPv6Network(x).Contains, config.campus6)

    def in_campus(ip):
        ip = IPv6Address(ip)
        for p in predicates:
            if p(ip):
                return True
        return False
    return in_campus

in_campus6 = _in_campus6_factory()

def _public_accessible_factory():
    predicates = map(lambda x: IPv4Network(x).Contains, config.campus_only)

    def public_accessible(ip):
        ip = IPv4Address(ip)
        for p in predicates:
            if p(ip):
                return False
        return True
    return public_accessible

public_accessible = _public_accessible_factory()


def make_answer(qname, qtype, content, qclass='IN', ttl=config.ttl, id_='-1'):
    """
    Makes a tuple that can be sent to pdns after joined by space.

    Supplies default values for the mostly invariant fields, and arranges all
    the fields in an order suitable for sending to pdns.
    """
    return (qname, qclass, qtype, ttl, id_, content)


def compose_soa(zone):
    """
    Makes an SOA record for a specific zone. It assumes that the primary DNS
    server has the domain name "dns." followed by the zone.
    """
    serial = strftime('%Y%m%d%H')
    ttl = config.ttl
    # XXX Hard-coded
    #      primary    hostmaster     serial          retry     ttl
    #                                           refresh  expire
    fmt = "dns.%(zone)s dns@%(zone)s %(serial)s 1200 600 28800 %(ttl)s"
    return fmt % locals()

connection = None

known_tags = list('46io')


def query_ipaddr(qtype, remote, tags, base):
    """
    Answers an A or AAA query by looking at the ipHostNumber attribute of the
    host objects.

    The qtype argument specifies the query type. The remote and tags arguments
    are used for filtering. The base argument is the LDAP DN for the host
    object to look at.
    """
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

    results = []
    if qtype in ('AAAA', 'ANY'):
        li = filter(is_v6, ips)
        results.extend([(addr, 'AAAA') for addr in li])
    if qtype in ('A', 'ANY'):
        li = filter(is_v4, ips)
        results.extend([(addr, 'A') for addr in li])

    return list(geo_filter(results, remote, tags)) or results


def query_raw(qtype, remote, tags, base):
    """
    Answers any type of query by looking at the *Record attributes of the
    host object. For instance, a TXT query may be answered by the TXTRecord
    attribute. Arguments are the same as those of query_ipaddr.
    """
    # XXX duplicate
    try:
        re = connection.search_s(base, ldap.SCOPE_BASE)
    except ldap.LDAPError as e:
        if not isinstance(e, ldap.NO_SUCH_OBJECT):
            output('LOG', 'Unusual LDAP exception: %s' % e)
            output('LOG', 'Base was: %s' % base)
        return []

    attr_dict = re[0][1]
    results = []

    for k, li in attr_dict.items():
        k = k.upper()
        if not k.endswith('RECORD'):
            continue
        t = k[:-len('RECORD')]
        if qtype == 'ANY' or qtype == t:
            results.extend([(r, t) for r in li])

    # print(results)
    return list(geo_filter(results, remote, tags)) or results


def geo_filter(results, remote, tags):
    # in_: result should be in campus
    # family: (None, 4, 6) -> (Any, 4, 6)

    if 'i' in tags:
        in_ = True
    elif 'o' in tags:
        in_ = False
    else:
        in_ = in_campus(remote)

    if '4' in tags:
        family = 4
    elif '6' in tags:
        family = 6
    else:
        family = None

    def always_true(x):
        return True

    accessible4 = campus_accessible if in_ else public_accessible
    accessible6 = in_campus6 if in_ else always_true

    for r, t in results:
        if t == "A" and accessible4(r) and family != 6:
            yield r, t
        elif t == "AAAA" and accessible6(r) and family != 4:
            yield r, t


def query(qname, qclass, qtype, id_, remote):
    """
    Answers a DNS query.
    """
    if qclass != 'IN':
        raise DNSError('Unsupported qclass: %s (expceted "IN")' % qclass)
    domain = Domain(qname.lower())
    edu_domain = None
    tags = set()
    if not hasattr(config, '_zone_domains'):
        config._zone_domains = [Domain(z) for z in config.zones]

    if not hasattr(config, '_edu_zone_domains'):
        config._edu_zone_domains = [Domain(z) for z in config.edu_zones]

    for zone in config._zone_domains:
        if domain <= zone:
            relative = domain[:-len(zone)]
            while relative and relative[-1] in known_tags:
                tags.add(relative.pop())
            break
    else:
        for zone in config._edu_zone_domains:
            if domain <= zone:
                edu_domain = domain[-3]
                relative = domain[:-len(zone)]
                while relative and relative[-1] in known_tags:
                    tags.add(relative.pop())
                break
        else:
            raise DNSError('Not in my zones: %s' % qname)

    answers = []

    searches = config.searches if edu_domain is None \
        else [config.edu_search(edu_domain)]
    raw_search = config.raw_search if edu_domain is None \
        else config.edu_raw_search(edu_domain)

    if qtype in ('A', 'AAAA', 'ANY'):

        def do_query_ipaddr(name):
            return query_ipaddr(qtype, remote, tags, fmt % escape_dn_chars(name))

        for fmt in searches:
            ips = do_query_ipaddr(str(relative) or '@')
            if not ips and len(relative) > 0:
                # Wildcard support.
                # Currently only cn=**.<dc> elements in the LDAP tree are
                # respected. <dc> is a single domain component, and the **
                # matches an arbitrary number of domain components.
                wild_relative = relative[-1:]
                wild_relative.appendleft('**')
                ips = do_query_ipaddr(str(wild_relative))
            if ips:
                more = [make_answer(qname, qtype_, ip) for ip, qtype_ in ips]
                answers.extend(more)
                break

    base = raw_search % escape_dn_chars(str(relative) or '@')
    more = [make_answer(qname, t, a % dict(zone=zone))
            for a, t in query_raw(qtype, remote, tags, base)]
    answers.extend(more)

    if len(relative) == 0 and qtype in ('SOA', 'ANY'):
        extra = make_answer(qname, 'SOA', compose_soa(str(zone)))
        answers.append(extra)

    return answers


def output(*fields):
    """
    Joins fields by tabs and write to stdout. This is the format expected by
    pdns. The fields must not contain tabs.
    """
    stdout.write('\t'.join(fields))
    stdout.write('\n')
    stdout.flush()


def respond(fields):
    """
    Takes a command from pdns and responds accordingly.
    """
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
            output('LOG', 'Shutting down on unexpected error. Traceback:')
            tb_lines = traceback.format_exc().split('\n')
            for line in tb_lines:
                output('LOG', line)
            break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        output('LOG', 'Interrupted by user when in non-daemon mode')
