aerospike-collectd
====================
Aerospike plugin for collectd.

Compatibility
=============
Fully compatible with Aerospike Server 4.0 - 5.0.0.11. Although, only tested on 4.9.0.11 and 5.0.0.11.

If you use a server version outside of 4.0 - 5.0.0.11 it should work fine but could be missing a few metrics.

Features
========
- Service Level Stats (`asinfo -v "statistics"`)
- Namespace Stats (`asinfo -v "namespace/NAMESPACE_NAME"`)
- Set Stats (`asinfo -v "sets/NAMESPACE_NAME/SET_NAME"`)
- Bin Stats (`asinfo -v "bins/NAMESPACE_NAME"`)
- SIndex Stats (`asinfo -v "sindex/NAMESPACE_NAME"`)
- Latency Stats (`asinfo -v "latency:"`)
- XDR Stats (`asinfo -v "dc/DC_NAME"`) & (`asinfo -v "get-stats:context=xdr;dc=DC_NAME`) 5.0+
- Can use Aerospike Security accounts

Requirements
============
Additional python modules are required and installed using pip:
```
sudo pip install -r requirements.txt
```

See requirements.txt

Install
=======

1. Clone the repository and place aerospike_types.db, aerospike_schema.yaml and aerospike_plugin.py somewhere accessible by collectd.
  * This is `/opt/collectd-plugins` for all 3 files files in the example below.
  * Ensure that `aerospike_plugin.py` is executable. (ie: chmod +x aerospike_plugin.py)
2. Drop aerospike.conf into the `collectd.conf.d` directory (typically found at /etc/collectd/collectd.conf.d)
or copy its contents into /etc/collectd/collectd.conf
3. Reload/restart collectd
4. Check that collectd is working fine:

```
tail -f /var/log/syslog
May 28 00:27:56 host1 collectd[21621]: Aerospike Plugin: client 127.0.0.1:3000
May 28 00:27:56 host1 collectd[21621]: Aerospike Plugin: Counter({'writes': 262, 'emits': 318})
May 28 00:28:06 host1 collectd[21621]: Aerospike Plugin: client 127.0.0.1:3000
May 28 00:28:06 host1 collectd[21621]: Aerospike Plugin: Counter({'writes': 262, 'emits': 318})
```

Note: If you run into errors about types.db not defined:

```
collectd[21431]: plugin_dispatch_values: Dataset not found: memory (from "host1/memory/memory-used"), check your types.db!
```

Edit the `/etc/collectd/collectd.conf` file and explicitly add (uncomment) the default types:

```
TypesDB "/usr/share/collectd/types.db"
```

Highlights from collectd.conf:

```
TypesDB  "/usr/share/collectd/types.db" "/opt/collectd-plugins/aerospike_types.db"

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
        # Prefix "cluster_name"
        # HostNameOverride "clusters.cluster_name.host_name"
    </Module>
</Plugin>
```

Authentication Support
======================

If Aerospike is configured with authentication, then you will need to configure the
plugin to authenticate.

To configure the username and password for authenticating the plugin, specify 
`User` and `Password` in the configuration as follows. `AuthMode` is optional 
parameter to specify authentication mode. It's default value is INTERNAL.

```
<Plugin python>
    ModulePath "/opt/collectd-plugins/"
    LogTraces true
    Interactive false
    Import "aerospike_plugin"
    <Module aerospike_plugin>
    	User "admin"
    	Password "admin"
    	AuthMode "EXTERNAL"
    </Module>
</Plugin>
```

SSL/TLS Support
===============

If Aerospike is configured with SSL/TLS, then you will need to configure the 
plugin with SSL/TLS as well.

SSL/TLS parameters are as follows:

```
<Plugin python>
    ModulePath "/opt/collectd-plugins/"
    Import "aerospike_plugin"

    <Module aerospike_plugin>

        Port "4333"
        TLSEnable true
        TLSName "my.aerospike.server"
#       TLSKeyfile ""
#       TLSKeyfilePw ""
#       TLSCertfile ""
        TLSCAFile "/etc/ssl/rootCA.pem"
#       TLSCAPath ""
#       TLSCipher "ALL"
#       TLSProtocols "all"
#       TLSBlacklist ""
#       TLSCRLCheck true
#       TLSCRLCheckAll true

    </Module>
</Plugin>
```

* **Port** - The secured port that Aerospike is listening on.
* **TLSEnable** - **Required** for TLS. Enable TLS plugin. Default False.
* **TLSName** - The hostname on the server's certificate. Required for normal auth and mutual auth.
* **TLSKeyfile** - The private key for your client cert. Required for mutual auth.
* **TLSKeyfilePw** - Decryption password for the private key. By default the key is assumed not to be encrypted.
* **TLSCertfile** - The certificate for your client. Required for mutual auth.
* **TLSCAFile** - **Required** The CA root certificate.
* **TLSCAPath** - The path to CAs and/or Certificate Revocation Lists.
* **TLSCipher** - The TLS Ciphers to use. See https://www.openssl.org/docs/man1.1.0/man1/ciphers.html for list of available ciphers. Must agree with server.
* **TLSProtocols** - The SSL/TLS protocols to use. 
* **TLSBlacklist** - A file containing the serial numbers of blacklisted certificates.
* **TLSCRLCheck** - Check against leaf certificates in the CRL chain.
* **TLSCRLCheckAll** - Check against all certificates in the CRL chain.


#### SSL/TLS Protocols
Available protocols are:
TLSv1, TLSv1.1, TLSv1.2

To use any supported protocol, a special keyword `all` may be used.

You can also include individual protocols by prepending a `+`, eg: `+TLSv1.1`.  
You can also exclude individual protocols by prepending a `-`, eg: `-TLSv1`.


### Examples

To use Server Side Authentication mode:

```
    <Module aerospike_plugin>
        Port "4333"
        TLSEnable true
        TLSName "my.aerospike.server"
        TLSCAFile "/etc/ssl/rootCA.pem" # Optional. Required for self-signed certs
    </Module>
```

To use Mutual Authentication mode:

```
    <Module aerospike_plugin>
        Port "4333"
        TLSEnable true
        TLSName "my.aerospike.server"
        TLSKeyfile "/etc/ssl/my.key"
        TLSCertfile "/etc/ssl/cert.pem"
        TLSCAFile "/etc/ssl/rootCA.pem"
    </Module>
```
