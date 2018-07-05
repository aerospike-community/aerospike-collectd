#!/usr/bin/env python
# ------------------------------------------------------------------------------
# Copyright 2012-2017 Aerospike, Inc.
#
# Portions may be licensed to Aerospike, Inc. under one or more contributor
# license agreements.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
# ------------------------------------------------------------------------------

import collectd
import os
import re
import socket
import struct
import time
import yaml

from ctypes import create_string_buffer


PLUGIN_NAME = 'aerospike'
PLUGIN_FILE = os.path.abspath(__file__)
PLUGIN_DIR = os.path.dirname(PLUGIN_FILE)

SCHEMA_LOCAL = os.path.join(PLUGIN_DIR, 'aerospike_schema.yaml')
SCHEMA_INSTALLED = '/opt/collectd-plugins/aerospike_schema.yaml'

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 3000
DEFAULT_TIMEOUT = 0.7

# =============================================================================
#
# Parsers
#
# -----------------------------------------------------------------------------


def value():
    def parse(input):
        if input == None:
            return None
        return input.strip()
    return parse


def pair(delim='=', key=value(), value=value()):
    def parse(input):
        if input is None:
            return None
        p = input.strip().strip(delim).split(delim, 1)
        lp = len(p)
        if lp == 2:
            (k, v) = p
            return (key(k), value(v))
        elif lp == 1:
            k = p[0]
            return (key(k), value(None))
        else:
            return (key(None), value(None))
    return parse


def seq(delim=';', entry=value()):
    def parse(input):
        if input is None:
            return None
        return (entry(e) for e in input.strip().strip(delim).split(delim))
    return parse


def pairs():
    return seq(entry=pair())


def clean(res):
    if res is None:
        return None
    res = res.strip().strip(';').strip(':').replace(';;', ';')
    if len(res) > 0:
        return res
    return None


def parse(input, parser=value()):
    return parser(clean(input)) if input is not None else input


# =============================================================================
#
# Counter
# Boosted from python 2.7 collections.Counter, sans comments and some methods.
#
# -----------------------------------------------------------------------------

class Counter(dict):

    def __init__(self, iterable=None, **kwds):
        self.update(iterable, **kwds)

    def __missing__(self, key):
        return 0

    @classmethod
    def fromkeys(cls, iterable, v=None):
        raise NotImplementedError(
            'Counter.fromkeys() is undefined.  Use Counter(iterable) instead.')

    def update(self, iterable=None, **kwds):
        if iterable is not None:
            if isinstance(iterable, Mapping):
                if self:
                    self_get = self.get
                    for elem, count in iterable.iteritems():
                        self[elem] = self_get(elem, 0) + count
                else:
                    dict.update(self, iterable)
            else:
                self_get = self.get
                for elem in iterable:
                    self[elem] = self_get(elem, 0) + 1
        if kwds:
            self.update(kwds)

    def subtract(self, iterable=None, **kwds):
        if iterable is not None:
            self_get = self.get
            if isinstance(iterable, Mapping):
                for elem, count in iterable.items():
                    self[elem] = self_get(elem, 0) - count
            else:
                for elem in iterable:
                    self[elem] = self_get(elem, 0) - 1
        if kwds:
            self.subtract(kwds)

    def copy(self):
        return Counter(self)

    def __delitem__(self, elem):
        if elem in self:
            dict.__delitem__(self, elem)

    def __repr__(self):
        if not self:
            return '%s()' % self.__class__.__name__
        items = ', '.join(map('%r: %r'.__mod__, self.iteritems()))
        return '%s({%s})' % (self.__class__.__name__, items)

    def __add__(self, other):
        if not isinstance(other, Counter):
            return NotImplemented
        result = Counter()
        for elem in set(self) | set(other):
            newcount = self[elem] + other[elem]
            if newcount > 0:
                result[elem] = newcount
        return result

    def __sub__(self, other):
        if not isinstance(other, Counter):
            return NotImplemented
        result = Counter()
        for elem in set(self) | set(other):
            newcount = self[elem] - other[elem]
            if newcount > 0:
                result[elem] = newcount
        return result


# =============================================================================
#
# Client
#
# -----------------------------------------------------------------------------

STRUCT_PROTO = struct.Struct('! Q')
STRUCT_AUTH = struct.Struct('! xxBB12x')
STRUCT_FIELD = struct.Struct('! IB')

MSG_VERSION = 0
MSG_TYPE = 2
AUTHENTICATE = 0
USER = 0
CREDENTIAL = 3
SALT = "$2a$10$7EqJtq98hPqEX7fNZaFWoO"


class ClientError(Exception):
    pass


class Client(object):

    def __init__(self, addr, port, timeout=0.7):
        self.addr = addr
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self, keyfile=None, certfile=None, ca_certs=None, ciphers=None, tls_enable=False, encrypt_only=False,
        capath=None, protocols=None, cert_blacklist=None, crl_check=False, crl_check_all=False, tls_name=None):
        s = None
        for res in socket.getaddrinfo(self.addr, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            ssl_context = None
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error as msg:
                s = None
                continue
            if tls_enable:
                from ssl_context import SSLContext
                from OpenSSL import SSL
                ssl_context = SSLContext(enable_tls=tls_enable, encrypt_only=encrypt_only, cafile=ca_certs, capath=capath,
                       keyfile=keyfile, certfile=certfile, protocols=protocols,
                       cipher_suite=ciphers, cert_blacklist=cert_blacklist,
                       crl_check=crl_check, crl_check_all=crl_check_all).ctx
                s = SSL.Connection(ssl_context,s)
            try:
                s.connect(sa)
                if ssl_context:
                    s.set_app_data(tls_name)
                    s.do_handshake()
            except socket.error as msg:
                s.close()
                s = None
                collectd.warning("Connect Error: %s" % msg)
                continue
            break

        if s is None:
            raise ClientError(
                "Could not connect to server at %s %s" % (self.addr, self.port))

        self.sock = s
        return self

    def close(self):
        if self.sock is not None:
            self.sock.settimeout(None)
            self.sock.close()
            self.sock = None

    def auth(self, username, password, timeout=None):

        import bcrypt

        if password == None:
            password = ''
        credential = bcrypt.hashpw(password, SALT)

        if timeout is None:
            timeout = self.timeout

        l = 8 + 16
        l += 4 + 1 + len(username)
        l += 4 + 1 + len(credential)

        buf = create_string_buffer(l)
        offset = 0

        proto = (MSG_VERSION << 56) | (MSG_TYPE << 48) | (l - 8)
        STRUCT_PROTO.pack_into(buf, offset, proto)
        offset += STRUCT_PROTO.size

        STRUCT_AUTH.pack_into(buf, offset, AUTHENTICATE, 2)
        offset += STRUCT_AUTH.size

        STRUCT_FIELD.pack_into(buf, offset, len(username) + 1, USER)
        offset += STRUCT_FIELD.size
        fmt = "! %ds" % len(username)
        struct.pack_into(fmt, buf, offset, username)
        offset += len(username)

        STRUCT_FIELD.pack_into(buf, offset, len(credential) + 1, CREDENTIAL)
        offset += STRUCT_FIELD.size
        fmt = "! %ds" % len(credential)
        struct.pack_into(fmt, buf, offset, credential)
        offset += len(credential)

        self.send(buf)

        buf = self.recv(8, timeout)
        rv = STRUCT_PROTO.unpack(buf)
        proto = rv[0]
        pvers = (proto >> 56) & 0xFF
        ptype = (proto >> 48) & 0xFF
        psize = (proto & 0xFFFFFFFFFFFF)

        buf = self.recv(psize, timeout)
        status = ord(buf[1])

        if status != 0:
            raise ClientError("Autentication Error %d for '%s' " %
                              (status, username))

    def send(self, data):
        if self.sock:
            try:
                r = self.sock.sendall(data)
            except IOError as e:
                raise ClientError(e)
            except socket.error as e:
                raise ClientError(e)
        else:
            raise ClientError('socket not available')

    def send_request(self, request, pvers=2, ptype=1):
        if request:
            request += '\n'
        sz = len(request) + 8
        buf = create_string_buffer(len(request) + 8)
        offset = 0

        proto = (pvers << 56) | (ptype << 48) | len(request)
        STRUCT_PROTO.pack_into(buf, offset, proto)
        offset = STRUCT_PROTO.size

        fmt = "! %ds" % len(request)
        struct.pack_into(fmt, buf, offset, request)
        offset = offset + len(request)

        self.send(buf)

    def recv(self, sz, timeout):
        out = ""
        pos = 0
        start_time = time.time()
        while pos < sz:
            buf = None
            try:
                buf = self.sock.recv(sz)
            except IOError as e:
                raise ClientError(e)
            if pos == 0:
                out = buf
            else:
                out += buf
            pos += len(buf)
            if timeout and time.time() - start_time > timeout:
                raise ClientError(socket.timeout())
        return out

    def recv_response(self, timeout=None):
        buf = self.recv(8, timeout)
        rv = STRUCT_PROTO.unpack(buf)
        proto = rv[0]
        pvers = (proto >> 56) & 0xFF
        ptype = (proto >> 48) & 0xFF
        psize = (proto & 0xFFFFFFFFFFFF)

        if psize > 0:
            return self.recv(psize, timeout)
        return ""

    def info(self, request):
        self.send_request(request)
        res = self.recv_response(timeout=self.timeout)
        out = re.split("\s+", res, maxsplit=1)
        if len(out) == 2:
            return out[1]
        else:
            raise ClientError("Failed to parse response: %s" % (res))


# =============================================================================
#
# Schema
#
# -----------------------------------------------------------------------------


class Schema(object):

    def __init__(self, schema={}):
        self.schema = schema
        self.mappings = {}

        for category, types in schema.iteritems():
            for type, metrics in types.iteritems():
                for i, metric in enumerate(metrics):
                    self.register(category, type, metric)

    def register(self, category, type, metric):
        m = self.mappings
        parts = metric.split(":", 2)
        if len(parts) == 2:
            name = parts[0]
            mapping = dict(parse(parts[1], pairs()))

            c = m.get(category, {})
            t = c.get(type, {})
            t[name] = mapping
            c[type] = t
            m[category] = c

    def lookup(self, category, name, val):
        types = self.schema[category] if category in self.schema else {}
        for type, metrics in types.iteritems():
            for m in metrics:
                if m == name:
                    yield type, self.value(name, category, val, type)

    def value(self, name, cat, val, type):

        if cat in self.mappings and type in self.mappings[cat] and name in self.mappings[cat][type]:
            mapping = self.mappings[cat][type][name]
            if val in mapping:
                val = mapping[val]
            elif '*' in mapping:
                val = mapping['*']

        if type == 'boolean':
            if str(val).lower() in ("false", "0"):
                val = 0
            else:
                val = 1

        return val


# =============================================================================
#
# Readers
#
# -----------------------------------------------------------------------------


def cluster(client, config, meta, emit):
    req = "services"
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        services = [parse(res, parser=seq())]
        emit(meta, 'services', len(services), ['cluster'])

    req = "services-alumni"
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        alumni = [parse(res, parser=seq())]
        emit(meta, 'services-alumni', len(alumni), ['cluster'])


def service(client, config, meta, emit):
    req = "statistics"
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        entries = parse(res, parser=pairs())
        for name, value in entries:
            emit(meta, name, value, ['service'])


def namespaces(client, config, meta, emit):
    req = "namespaces"
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        namespaces = parse(res, parser=seq())
        for name in namespaces:
            namespace(client, config, meta, emit, name)


def namespace(client, config, meta, emit, namespace):
    req = "namespace/%s" % (namespace)
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        entries = parse(res, parser=pairs())
        for name, value in entries:
            emit(meta, name, value, ['namespace', namespace])


def datacenters(client, config, meta, emit):

    if config.get("enable-xdr", "false") == "false":
        return

    req = "get-dc-config"
    res = None

    try:
        res = client.info(req)
        if res is None or len(res) == 0:
            return
    except ClientError as e:
        # If this fails, then it likely means it is not Aerospike EE
        # so we reduce this to a debug message
        collectd.debug('Failed to execute info "%s" - %s' % (req, e))
    else:
        datacenters = parse(res, seq())
        for entry in datacenters:
            dc = dict(parse(entry, seq(entry=pair(), delim=':')))
            datacenter(client, config, meta, emit, dc)


def datacenter(client, config, meta, emit, dc):

    try:
        dcname = dc['DC_Name']
    except:
        dcname = dc['dc-name']
    req = "dc/%s" % dcname
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        entries = parse(res, parser=pairs())
        for name, value in entries:
            emit(meta, name, value, ['datacenter', dcname])


def latency(client, config, meta, emit):
    req = "latency:"
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        res = res.strip()
        if res.endswith(';'):
            res=res[:-1] # 3.9+ releases stripped out a trailing ';'
        tdata = res.split(';')
        while tdata != []:
            columns = tdata.pop(0)
            # keep popping if there's a line with error
            while columns.startswith('error'):
                if tdata == []:
                    # tdata is empty, return
                    return
                columns = tdata.pop(0)
            row = tdata.pop(0)

            hist_name, columns = columns.split(':', 1)

            # parse dynamic metrics
            shortname = re.sub('{.*}-','',hist_name)
            match = re.match('{(.*)}',hist_name)
            context = ["latency"]
            if match:
                namespace = match.groups()[0]
                context.append(namespace)
            columns = columns.split(',')
            row = row.split(',')

            # Get rid of duration data
            columns.pop(0)
            row.pop(0)
            row = [float(r) for r in row]

            # Don't need TPS column name
            columns.pop(0)
            name = "%s_tps" % (shortname)
            value = row.pop(0)
            emit(meta, name, value, context)

            while columns:
                name = "%s_pct%s" % (shortname, columns.pop(0))
                name = name.replace(">", "_gt_")
                value = row.pop(0)
                emit(meta, name, value, context)


# =============================================================================
#
# Plugin
#
# -----------------------------------------------------------------------------

class Plugin(object):

    def __init__(self, readers=[]):

        self.plugin_name = PLUGIN_NAME
        self.readers = readers

        # configurable via collectd.conf
        self.host = DEFAULT_HOST
        self.port = DEFAULT_PORT
        self.timeout = DEFAULT_TIMEOUT
        self.schema_path = None
        self.username = None
        self.password = None
        self.tls_enable = False
        self.tls_keyfile = None
        self.tls_certfile = None
        self.tls_ca = None
        self.tls_capath = None
        self.tls_version = None
        self.tls_cipher = None
        self.encrypt_only = False
        self.tls_protocols = None
        self.tls_blacklist = None
        self.tls_crlcheck = False
        self.tls_crlcheckall = False
        self.tls_name = None

        # prefixing is not yet supported
        # I personally think it is best to not do it in the plugin
        # self.prefix = None
        # self.host_name = None

        # collected during runtime
        self.node_id = None
        self.schema = None
        self.initialized = False

    def config(self, obj):
        for node in obj.children:
            collectd.warning("Param: %s, Value %s"%(node.key, node.values[0]))
            if node.key == 'Host':
                self.host = node.values[0]
            elif node.key == 'Port':
                self.port = int(node.values[0])
            elif node.key == 'Timeout':
                self.timeout = float(node.values[0])
            elif node.key == 'User':
                self.username = node.values[0]
            elif node.key == 'Password':
                self.password = node.values[0]
            # elif node.key == 'Prefix':
            #     self.prefix = node.values[0]
            # elif node.key == 'HostNameOverride':
            #     self.host_name = node.values[0]
            elif node.key == 'Schema':
                self.schema_path = node.values[0]
            elif node.key == 'TLSEnable':
                self.tls_enable = node.values[0]
            elif node.key == 'TLSKeyfile':
                self.tls_keyfile = node.values[0]
            elif node.key == 'TLSCertfile':
                self.tls_certifile = node.values[0]
            elif node.key == 'TLSCAFile':
                self.tls_ca = node.values[0]
            elif node.key == 'TLSCAPath':
                self.tls_capath = node.values[0]
            elif node.key == 'TLSVersion':
                self.tls_version = node.values[0]
            elif node.key == 'TLSCipher':
                self.tls_cipher = node.values[0]
            elif node.key == 'EncryptOnly':
                self.encrypt_only = node.values[0]
            elif node.key == 'TLSProtocols':
                self.tls_protocols = node.values[0]
            elif node.key == 'TLSBlacklist':
                self.tls_blacklist == node.values[0]
            elif node.key == 'TLSCRL':
                self.tls_crlcheck == node.values[0]
            elif node.key == 'TLSCRLCheck':
                self.tls_crlcheckall == node.values[0]
            elif node.key == 'TLSName':
                self.tls_name = node.values[0]
            else:
                collectd.warning('%s: Unknown configuration key %s' % (
                    self.plugin_name, node.key))

    def setup(self):

        if self.initialized:
            return

        if not self.schema_path:
            if os.path.isfile(SCHEMA_LOCAL):
                self.schema_path = SCHEMA_LOCAL
            elif os.path.isfile(SCHEMA_INSTALLED):
                self.schema_path = SCHEMA_INSTALLED
            else:
                collectd.warning('Failed to find schema: %s, %s' %
                                 (SCHEMA_LOCAL, SCHEMA_INSTALLED))

        if self.schema_path:
            collectd.info('Aerospike Plugin: schema %s' % self.schema_path)
            with open(self.schema_path) as schema_file:
                self.schema = Schema(yaml.load(schema_file))

        self.initialized = True

    def emit(self, meta, name, value, context):
        meta['emits'] += 1
        category = context[0]
        for type, value in self.schema.lookup(category, name, value):
            try:
                val = collectd.Values()
                val.plugin = self.plugin_name
                val.plugin_instance = ".".join(context)
                val.type = type
                val.type_instance = name
                # HACK with this dummy dict in place JSON parsing works
                # https://github.com/collectd/collectd/issues/716
                val.meta = {'0': True}
                val.values = [value, ]
                val.dispatch()
                meta['writes'] += 1
            except Exception as e:
                collectd.warning("Error sending data:")
                collectd.warning("Category %s, Name %s, Value %s, Type %s"%(category,name,value,type))
                collectd.warning(str(e))


    def read(self):
        addr = self.host
        port = self.port
        username = self.username
        password = self.password
        keyfile = self.tls_keyfile
        certfile = self.tls_certfile
        ca = self.tls_ca
        ca_path = self.tls_capath
        tls_enable = self.tls_enable
        cipher = self.tls_cipher
        protocols = self.tls_protocols
        encrypt_only = self.encrypt_only
        blacklist = self.tls_blacklist
        crl_check = self.tls_crlcheck
        crl_check_all = self.tls_crlcheckall
        tls_name = self.tls_name
        meta = Counter()
        alive = 0

        self.setup()

        collectd.info("Aerospike Plugin: client %s:%s" % (addr, port))
        client = Client(addr=addr, port=port,)

        try:
            client.connect(keyfile=keyfile, certfile=certfile, ca_certs=ca,ciphers=cipher,tls_enable=tls_enable, encrypt_only=encrypt_only, \
                capath=ca_path, protocols=protocols, cert_blacklist=blacklist, crl_check=crl_check, crl_check_all=crl_check_all, tls_name=tls_name)
            if username:
                collectd.info('Aerospike Plugin: auth %s' % username)
                status = client.auth(username, password)

        except ClientError as e:
            collectd.warning('Failed to connect to %s:%s - %s' %
                             (addr, port, e))
            meta['failures'] += 1
        else:

            req = "node"
            res = None
            try:
                res = client.info(req)
            except ClientError as e:
                collectd.warning(
                    'Failed to execute info: "%s" - %s' % (req, e))
            else:
                self.node_id = res

            req = "get-config"
            res = None
            try:
                res = client.info(req)
            except ClientError as e:
                collectd.warning(
                    'Failed to execute info: "%s" - %s' % (req, e))
            else:

                config = dict(parse(res, pairs()))

                for reader in self.readers:
                    reader(client, config, meta, self.emit)
            alive = 1
        finally:
            client.close()

        # record meta here.
        collectd.info('Aerospike Plugin: %s' % str(meta))
        self.emit(meta, 'emits', meta['emits'], ['meta'])
        self.emit(meta, 'writes', meta['writes'], ['meta'])
        self.emit(meta, 'timeouts', meta['timeouts'], ['meta'])
        self.emit(meta, 'failures', meta['failures'], ['meta'])
        self.emit(meta, 'alive', alive, ['meta'])


# =============================================================================

plugin = Plugin(readers=[
    cluster,
    service,
    namespaces,
    datacenters,
    latency,
])
collectd.register_read(plugin.read)
collectd.register_config(plugin.config)
