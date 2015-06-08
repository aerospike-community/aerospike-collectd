# aerospike-collectd
Aerospike plugin for collectd.

# Warning
This package is in early development; backwards compatibility is not
presently considered.

# Install

```
sudo pip install -r requirements.txt
```

Highlights from collectd.conf:

```
TypesDB "/opt/collectd-plugins/aerospike_types.db"

<LoadPlugin python>
    Globals true
</LoadPlugin>

<Plugin python>
    ModulePath "/opt/collectd-plugins/"
    LogTraces true
    Interactive false
    Import "aerospike_plugin"
    <Module aerospike_plugin>
        Host   "127.0.0.1"
        Port   3000
        Prefix "cluster_name"
    </Module>
</Plugin>
```

# Features:
- Service Level Stats (`asinfo -v "statistics"`)
- Namespace Stats (`asinfo -v "namespace/NAMESPACE_NAME"`)
- Latency Stats (`asinfo -v "latency:"`)
- Can use Aerospike Security accounts
- (TODO) Configuration Stats (`asinfo -v "get-config:context=CONTEXT"`)
- (TODO) XDR Stats (`asinfo -p 3004 -v "get-config:context=service"`)
- (TODO) Optionally disable stats (DisableXDR true)
