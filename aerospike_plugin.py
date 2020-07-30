#!/usr/bin/env python
# ------------------------------------------------------------------------------
# Copyright 2012-2019 Aerospike, Inc.
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

__author__ = "Aerospike"
__copyright__ = "Copyright 2019 Aerospike"
__version__ = "2.0.0"

import aerospike
import collectd
import os
import re
import yaml


PLUGIN_NAME = 'aerospike'
PLUGIN_FILE = os.path.abspath(__file__)
PLUGIN_DIR = os.path.dirname(PLUGIN_FILE)

SCHEMA_LOCAL = os.path.join(PLUGIN_DIR, 'aerospike_schema.yaml')
SCHEMA_INSTALLED = '/opt/collectd-plugins/aerospike_schema.yaml'

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 3000
DEFAULT_TIMEOUT = 5

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


class Enumeration(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

    def __getitem__(self, name):
        if name in self:
            return name
        raise AttributeError

AuthMode = Enumeration([
    # Use internal authentication only.  Hashed password is stored on the server.
	# Do not send clear password. This is the default.

	"INTERNAL",

    # Use external authentication (like LDAP).  Specific external authentication is
	# configured on server.  If TLS defined, send clear password on node login via TLS.
	# Throw exception if TLS is not defined.

	"EXTERNAL",

    # Use external authentication (like LDAP).  Specific external authentication is
	# configured on server.  Send clear password on node login whether or not TLS is defined.
	# This mode should only be used for testing purposes because it is not secure authentication.

	"EXTERNAL_INSECURE",
])

class ClientError(Exception):
    pass


class Client(object):

    def __init__(self, addr, port, tls_enable=False, tls_name=None, tls_keyfile=None, tls_keyfile_pw=None, tls_certfile=None,
                 tls_cafile=None, tls_capath=None, tls_cipher=None, tls_protocols=None, tls_cert_blacklist=None,
                 tls_crl_check=False, tls_crl_check_all=False, auth_mode=aerospike.AUTH_INTERNAL, timeout=DEFAULT_TIMEOUT):
        self.addr = addr
        self.port = port
        self.tls_name = tls_name
        self.timeout = timeout
        self.host = (self.addr, self.port)
        if self.tls_name:
            self.host = (self.addr, self.port, self.tls_name)

        tls_config = {
            'enable': tls_enable
        }

        if tls_enable:
            tls_config = {
                'enable': tls_enable,
                'keyfile': tls_keyfile,
                'keyfile_pw': tls_keyfile_pw,
                'certfile': tls_certfile,
                'cafile': tls_cafile,
                'capath': tls_capath,
                'cipher_suite': tls_cipher,
                'protocols': tls_protocols,
                'cert_blacklist': tls_cert_blacklist,
                'crl_check': tls_crl_check,
                'crl_check_all': tls_crl_check_all
            }

        config = {
            'hosts': [
                self.host
            ],

            'policies': {
                'timeout': self.timeout*1000,
                'auth_mode': auth_mode
            },

            'tls': tls_config
        }

        self.asClient = aerospike.client(config)


    def connect(self, username=None, password=None):
        try:
            self.asClient.connect(username, password)
        except Exception as e:
            raise ClientError("Could not connect to server at %s %s: %s" % (self.addr, self.port, str(e)))

    def close(self):
        if self.asClient is not None:
            self.asClient.close()
            self.asClient = None

    def info(self, request):
        read_policies = {'total_timeout': self.timeout}

        res = self.asClient.info_node(request, self.host, policy=read_policies)
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
                for _, metric in enumerate(metrics):
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
            if name in metrics:
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
        if name == "cluster_key" or name == "cluster_principal" or name == "paxos_principal":
            val = int(val,16)
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
            dc = dict(parse(entry, seq(delim=':', entry=pair())))
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

def bins(client, config, meta, emit):
    req = "bins"
    res = None

    try:
        res = client.info(req)
        if res is None or len(res) == 0:
            return
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        bins = parse(res, seq())
        for bin in bins:
            namespace, metrics = bin.split(':')
            entries = parse(metrics, seq(delim=',', entry=pair()))
            for name, value in entries:
                emit(meta, name, value, ['bins', namespace])

def sets(client, config, meta, emit):
    req = "sets"
    res = None

    try:
        res = client.info(req)
        if res is None or len(res) == 0:
            return
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        sets = parse(res, seq())
        for _set in sets:
            entries = parse(_set, seq(delim=':', entry=pair()))
            entries_dict = dict(
                parse(_set, seq(delim=':', entry=pair())))
            namespace = entries_dict['ns']
            set_name = entries_dict['set']
            for name, value in entries:
                emit(meta, name, value, ['sets', namespace, set_name])

def sindexes(client, config, meta, emit):
    req = 'sindex'
    res = None

    try:
        res = client.info(req)
        if res is None or len(res) == 0:
            return
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        sindexes = parse(res, seq())
        for sidx in sindexes:
            sidx = dict(parse(sidx,
                                    seq(delim=':', entry=pair())))
            sindex(client, config, meta, emit, sidx)


def sindex(client, config, meta, emit, sidx):
    namespace = sidx['ns']
    index_name = sidx['indexname']

    req = "sindex/%s/%s" % (namespace, index_name)
    res = None

    try:
        res = client.info(req)
    except ClientError as e:
        collectd.warning('Failed to execute info "%s" - %s' % (req, e))
        meta['timeouts'] += 1
    else:
        entries = parse(res, parser=pairs())
        for name, value in entries:
            emit(meta, name, value, ['sindex', namespace, index_name])



        


# =============================================================================
#
# Plugin
#
# -----------------------------------------------------------------------------

class Plugin(object):

    def __init__(self, readers=[]):

        self.client = None
        self.plugin_name = PLUGIN_NAME
        self.readers = readers

        # configurable via collectd.conf
        self.host = DEFAULT_HOST
        self.port = DEFAULT_PORT
        self.timeout = DEFAULT_TIMEOUT
        self.schema_path = None

        self.username = None
        self.password = None
        self.auth_mode = aerospike.AUTH_INTERNAL

        self.tls_enable = False
        self.tls_name = None
        self.tls_keyfile = None
        self.tls_keyfile_pw = None
        self.tls_certfile = None
        self.tls_cafile = None
        self.tls_capath = None
        self.tls_cipher = None
        self.tls_protocols = None
        self.tls_cert_blacklist = None
        self.tls_crl_check = False
        self.tls_crl_check_all = False

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
            elif node.key == 'AuthMode':
                if node.values[0] == AuthMode.EXTERNAL:
                    self.auth_mode = aerospike.AUTH_EXTERNAL
                elif node.values[0] == AuthMode.EXTERNAL_INSECURE:
                    self.auth_mode = aerospike.AUTH_EXTERNAL_INSECURE

            # elif node.key == 'Prefix':
            #     self.prefix = node.values[0]
            # elif node.key == 'HostNameOverride':
            #     self.host_name = node.values[0]

            elif node.key == 'Schema':
                self.schema_path = node.values[0]

            elif node.key == 'TLSEnable':
                self.tls_enable = node.values[0]
            elif node.key == 'TLSName':
                self.tls_name = node.values[0]
            elif node.key == 'TLSKeyfile':
                self.tls_keyfile = node.values[0]
            elif node.key == 'TLSKeyfilePw':
                self.tls_keyfile_pw = node.values[0]
            elif node.key == 'TLSCertfile':
                self.tls_certfile = node.values[0]
            elif node.key == 'TLSCAFile':
                self.tls_cafile = node.values[0]
            elif node.key == 'TLSCAPath':
                self.tls_capath = node.values[0]
            elif node.key == 'TLSCipher':
                self.tls_cipher = node.values[0]
            elif node.key == 'EncryptOnly':
                self.encrypt_only = node.values[0]
            elif node.key == 'TLSProtocols':
                self.tls_protocols = node.values[0]
            elif node.key == 'TLSBlacklist':
                self.tls_blacklist = node.values[0]
            elif node.key == 'TLSCRLCheck':
                self.tls_crl_check = node.values[0]
            elif node.key == 'TLSCRLCheckAll':
                self.tls_crl_check_all = node.values[0]

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

    def init_client(self):

        collectd.info("Aerospike Plugin: client %s:%s" % (self.host, self.port))
        self.client = Client(addr=self.host, port=self.port, tls_enable=self.tls_enable, tls_name=self.tls_name,
                        tls_keyfile=self.tls_keyfile, tls_keyfile_pw=self.tls_keyfile_pw, tls_certfile=self.tls_certfile,
                        tls_cafile=self.tls_cafile, tls_capath=self.tls_capath, tls_cipher=self.tls_cipher,
                        tls_protocols=self.tls_protocols, tls_cert_blacklist=self.tls_cert_blacklist,
                        tls_crl_check=self.tls_crl_check, tls_crl_check_all=self.tls_crl_check_all,
                        auth_mode=self.auth_mode, timeout=self.timeout)

        try:
            self.client.connect(username=self.username, password=self.password)

        except ClientError as e:
            if self.client:
                self.client.close()
                self.client = None
            raise e

    def init(self):
        meta = Counter()
        self.setup()

        try:
            self.init_client()
        except ClientError as e:
            collectd.warning('Failed to connect to %s:%s - %s' %
                             (self.host, self.port, e))
            meta['failures'] += 1

    def shutdown(self):
        if self.client:
            self.client.close()
            self.client = None

    def emit(self, meta, name, value, context):
        meta['emits'] += 1
        category = context[0]
        names = name.rsplit('.',1)    # new 4.3 metric schema: storage-engine.$device[X].$metric
        metric = names.pop()
        prefix = ""
        plugin_instance = ".".join(context)
        if names:
            prefix = names.pop()
            # intermediary schema is held in 'name' variable
            # move intermediary up, since schema is hostname.pluging-plugin_instance.type-type_instance
            plugin_instance += "."+prefix.replace('[','').replace(']','') 
        for type, value in self.schema.lookup(category, metric, value):
            try:
                val = collectd.Values()
                val.plugin = self.plugin_name
                val.plugin_instance = plugin_instance
                val.type = type
                val.type_instance = metric
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
        meta = Counter()
        alive = 0

        try:
            if not self.client:
                self.init_client()

        except ClientError as e:
            collectd.warning('Failed to connect to %s:%s - %s' %
                             (self.host, self.port, e))
            meta['failures'] += 1

        else:
            if self.client:
                req = "node"
                res = None
                try:
                    res = self.client.info(req)
                except ClientError as e:
                    collectd.warning('Failed to execute info: "%s" - %s' % (req, e))
                else:
                    self.node_id = res

                req = "get-config"
                res = None
                try:
                    res = self.client.info(req)
                except ClientError as e:
                    collectd.warning('Failed to execute info: "%s" - %s' % (req, e))
                else:

                    config = dict(parse(res, pairs()))

                    for reader in self.readers:
                        reader(self.client, config, meta, self.emit)
                alive = 1

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
    bins,
    sets,
    sindexes
])

collectd.register_init(plugin.init)
collectd.register_config(plugin.config)
collectd.register_read(plugin.read)
collectd.register_shutdown(plugin.shutdown)

