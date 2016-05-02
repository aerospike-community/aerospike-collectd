aerospike-collectd
====================
Aerospike plugin for collectd.

Version 1.0 is not compatible with previous 0.x releases due to metrics being renamed.
For the older releases. Please see the "master" branch.

Install
=======

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
