aerospike-collectd
====================
Aerospike plugin for collectd.

Version 1.0 is not compatible with previous 0.x releases due to metrics being renamed.


Install
=======

```
sudo pip install -r requirements.txt
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
</Plugin>
```

Features
========
- Service Stats
- Namespace Stats
- Transaction Stats
- XDR Stats

Authentication Support
======================

If Aerospike is configured with authentication, then you will need to configure the
plugin to authenticate. The plugin requires python bcrypt to be installed:

```
pip install bcrypt
```

To configure the username and password for authenticating the plugin, specify 
`User` and `Password` in the configuration as follows.

```
<Plugin python>
    ModulePath "/opt/collectd-plugins/"
    LogTraces true
    Interactive false
    Import "aerospike_plugin"
    <Module aerospike_plugin>
    	User "admin"
    	Password "admin"
    </Module>
</Plugin>
```

SSL/TLS Support
===============

If Aerospike is configured with SSL/TLS, then you will need to configure the 
plugin with SSL/TLS as well. The plugin requires python pyOpenSSL to be installed:

```
pip install pyOpenSSL
```

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
* **TLSCipher** - The TLS Ciphers to use. See https://www.openssl.org/docs/man1.0.1/apps/ciphers.html for list of available ciphers. Must agree with server.
* **TLSProtocols** - The SSL/TLS protocols to use. 
* **TLSBlacklist** - A file containing the serial numbers of blacklisted certificates.
* **TLSCRLCheck** - Check against leaf certificates in the CRL chain.
* **TLSCRLCheckAll** - Check against all certificates in the CRL chain.


#### SSL/TLS Protocols
Available protocols are:
TLSv1, TLSv1.1, TLSv1.2

To use any supported protocol, a special keyword `all` may be used.

You can also include individual protocols by prepending a `+`, eg: `+TLSv1.1`.  
You can also exclude individual protocols by prepending a `-`, eg `-TLSv1`.


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
