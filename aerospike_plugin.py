#!/usr/bin/python

import aerospike
from aerospike.exception import TimeoutError, ClientError
import itertools
import re
import pprint

import collectd

class Data(object):
    pass

class AerospikePlugin(object):
    def __init__(self):
        self.plugin_name = "aerospike"
        self.prefix = None
        self.host_name = None
        self.aerospike = Data()
        self.aerospike.host = "127.0.0.1"
        self.aerospike.port = 3000
        self.aerospike.user = None
        self.aerospike.password = None
        self.node_id = None
        self.timeout = 2000

    def submit(self, value_type, instance, value, context, use_node_id=True):
        plugin_instance = []
        if self.prefix:
            plugin_instance.append(self.prefix)

        if use_node_id:
          plugin_instance.append(self.node_id)
        plugin_instance.append(context)

        plugin_instance = ".".join(plugin_instance)
        data = pprint.saferepr((value_type,plugin_instance,instance
                               ,value,context))
        collectd.debug("Dispatching: %s"%(data))

        val = collectd.Values()
        if self.host_name:
            val.host = self.host_name
        val.plugin = self.plugin_name
        val.plugin_instance = plugin_instance
        val.type = value_type
        val.type_instance = instance.lower().replace('-', '_')
        # HACK with this dummy dict in place JSON parsing works
        # https://github.com/collectd/collectd/issues/716
        val.meta = {'0': True}
        val.values = [value, ]
        val.dispatch()

    def process_statistics(self, meta_stats, statistics, context, counters=None
                           , counts=None, storage=None, booleans=None
                           , percents=None, operations=None, config=None):
        if counters is None:
            counters = set()
        if counts is None:
            counts = set()
        if storage is None:
            storage = set()
        if booleans is None:
            booleans = set()
        if percents is None:
            percents = set()
        if operations is None:
            operations = set()
        if config is None:
            config = set()
        for key, value in statistics.iteritems():
            if key in counters:
                value_type = "count"
            elif key in counts:
                value_type = "count"
            elif key in booleans:
                value_type = "boolean"
                value = value.lower()
                if value == "false" or value == "no" or value == "0" or value == "CLUSTER_DOWN":
                    value = 0
                else:
                    value = 1
            elif key in percents:
                value_type = "percent"
            elif key in storage:
                value_type = "bytes"
            elif key in operations:
                value_type = "count"
            elif key in config:
                continue
            else:
                try:
                    float(value)
                except ValueError:
                    pass
                else:
                    # Log numeric values that aren't emitted
                    stat_name = "%s.%s"%(context, key)

                    collectd.info("Unused numeric stat: %s has value %s"%(
                        stat_name, value))
                    meta_stats["unknown_metrics"] += 1
                continue

            self.submit(value_type, key, value, context)

    def do_service_statistics(self, meta_stats, client, hosts):
        counters = set(["uptime",])

        counts = set([
            "batch_queue"
            , "batch_tree_count"
            , "client_connections"
            , "cluster_size"
            , "delete_queue"
            , "info_queue"
            , "migrate_progress_recv"
            , "migrate_progress_send"
            , "migrate_rx_objs"
            , "migrate_tx_objs"
            , "objects"
            , "ongoing_write_reqs"
            , "partition_absent"
            , "partition_actual"
            , "partition_desync"
            , "partition_object_count"
            , "partition_ref_count"
            , "partition_replica"
            , "proxy_in_progress"
            , "queue"
            , "record_locks"
            , "record_refs"
            , "stat_evicted_objects_time"
            , "sub-records"
            , "tree_count"
            , "waiting_transactions"
            , "query_long_queue_size"
            , "query_short_queue_size"
        ])

        booleans = set([
            "cluster_integrity"
            , "system_swapping"
        ])

        percents = set([
            "free-pct-disk"
            , "free-pct-memory"
            , "system_free_mem_pct"
        ])

        storage = set([
            "data-used-bytes-memory"
            , "index-used-bytes-memory"
            , "sindex-used-bytes-memory"
            , "total-bytes-disk"
            , "total-bytes-memory"
            , "used-bytes-disk"
            , "used-bytes-memory"
        ])

        operations = set([
            "aggr_scans_succeeded"
            , "aggr_scans_failed"
            , "basic_scans_failed"
            , "basic_scans_succeeded"
            , "batch_errors"
            , "batch_index_initiate"
            , "batch_index_complete"
            , "batch_index_timeout"
            , "batch_index_errors"
            , "batch_index_unused_buffers"
            , "batch_index_huge_buffers"
            , "batch_index_created_buffers"
            , "batch_index_destroyed_buffers"
            , "batch_initiate"
            , "batch_timeout"
            , "err_duplicate_proxy_request"
            , "err_out_of_space"
            , "err_replica_non_null_node"
            , "err_replica_null_node"
            , "err_rw_cant_put_unique"
            , "err_rw_pending_limit"
            , "err_rw_request_not_found"
            , "err_storage_queue_full"
            , "err_sync_copy_null_master"
            , "err_sync_copy_null_node"
            , "err_tsvc_requests"
            , "err_tsvc_requests_timeout"
            , "err_write_fail_bin_exists"
            , "err_write_fail_bin_name"
            , "err_write_fail_bin_not_found"
            , "err_write_fail_forbidden"
            , "err_write_fail_generation"
            , "err_write_fail_generation_xdr"
            , "err_write_fail_incompatible_type"
            , "err_write_fail_key_exists"
            , "err_write_fail_key_mismatch"
            , "err_write_fail_not_found"
            , "err_write_fail_noxdr"
            , "err_write_fail_parameter"
            , "err_write_fail_prole_delete"
            , "err_write_fail_prole_generation"
            , "err_write_fail_prole_unknown"
            , "err_write_fail_record_too_big"
            , "err_write_fail_unknown"
            , "fabric_msgs_rcvd"
            , "fabric_msgs_sent"
            , "heartbeat_received_foreign"
            , "heartbeat_received_self"
            , "migrate_msgs_recv"
            , "migrate_msgs_sent"
            , "migrate_num_incoming_accepted"
            , "migrate_num_incoming_refused"
            , "proxy_action"
            , "proxy_initiate"
            , "proxy_retry"
            , "proxy_retry_new_dest"
            , "proxy_retry_q_full"
            , "proxy_retry_same_dest"
            , "proxy_unproxy"
            , "query_abort"
            , "query_agg"
            , "query_agg_abort"
            , "query_agg_avg_rec_count"
            , "query_agg_err"
            , "query_agg_success"
            , "query_avg_rec_count"
            , "query_fail"
            , "query_long_queue_full"
            , "query_long_reqs"
            , "query_long_running"
            , "query_lookup_abort"
            , "query_lookup_avg_rec_count"
            , "query_lookup_err"
            , "query_lookups"
            , "query_lookup_success"
            , "query_reqs"
            , "query_short_queue_full"
            , "query_short_reqs"
            , "query_short_running"
            , "query_success"
            , "query_tracked"
            , "read_dup_prole"
            , "reaped_fds"
            , "rw_err_ack_badnode"
            , "rw_err_ack_internal"
            , "rw_err_ack_nomatch"
            , "rw_err_dup_cluster_key"
            , "rw_err_dup_internal"
            , "rw_err_dup_send"
            , "rw_err_write_cluster_key"
            , "rw_err_write_internal"
            , "rw_err_write_send"
            , "scans_active"
            , "sindex_gc_activity_dur"
            , "sindex_gc_garbage_cleaned"
            , "sindex_gc_garbage_found"
            , "sindex_gc_inactivity_dur"
            , "sindex_gc_list_creation_time"
            , "sindex_gc_list_deletion_time"
            , "sindex_gc_locktimedout"
            , "sindex_gc_objects_validated"
            , "sindex_ucgarbage_found"
            , "stat_cluster_key_err_ack_dup_trans_reenqueue"
            , "stat_cluster_key_err_ack_rw_trans_reenqueue"
            , "stat_cluster_key_partition_transaction_queue_count"
            , "stat_cluster_key_prole_retry"
            , "stat_cluster_key_regular_processed"
            , "stat_cluster_key_transaction_reenqueue"
            , "stat_cluster_key_trans_to_proxy_retry"
            , "stat_deleted_set_objects"
            , "stat_delete_success"
            , "stat_duplicate_operation"
            , "stat_evicted_objects"
            , "stat_expired_objects"
            , "stat_ldt_proxy"
            , "stat_nsup_deletes_not_shipped"
            , "stat_evicted_set_objects"
            , "stat_proxy_errs"
            , "stat_proxy_reqs"
            , "stat_proxy_reqs_xdr"
            , "stat_proxy_success"
            , "stat_read_errs_notfound"
            , "stat_read_errs_other"
            , "stat_read_reqs"
            , "stat_read_reqs_xdr"
            , "stat_read_success"
            , "stat_rw_timeout"
            , "stat_slow_trans_queue_batch_pop"
            , "stat_slow_trans_queue_pop"
            , "stat_slow_trans_queue_push"
            , "stat_write_errs"
            , "stat_write_errs_notfound"
            , "stat_write_errs_other"
            , "stat_write_reqs"
            , "stat_write_reqs_xdr"
            , "stat_write_success"
            , "stat_xdr_pipe_miss"
            , "stat_xdr_pipe_writes"
            , "stat_zero_bin_records"
            , "storage_defrag_corrupt_record"
            , "transactions"
            , "tscan_aborted"
            , "tscan_initiate"
            , "tscan_pending"
            , "tscan_succeeded"
            , "udf_bg_scans_succeeded"
            , "udf_bg_scans_failed"
            , "udf_delete_err_others"
            , "udf_delete_reqs"
            , "udf_delete_success"
            , "udf_lua_errs"
            , "udf_query_rec_reqs"
            , "udf_read_errs_other"
            , "udf_read_reqs"
            , "udf_read_success"
            , "udf_replica_writes"
            , "udf_scan_rec_reqs"
            , "udf_write_err_others"
            , "udf_write_reqs"
            , "udf_write_success"
            , "write_master"
            , "write_prole"
        ])

        try:
            _, (_, statistics) = client.info("statistics", hosts=hosts).items()[0]
        except (TimeoutError, ClientError):
            collectd.warning('WARNING: TimeoutError executing info("statistics")')
            meta_stats["timeouts"] += 1
        else:
            statistics = info_to_dict(statistics)
            self.process_statistics(meta_stats
                                    , statistics
                                    , "service"
                                    , counters=counters
                                    , counts=counts
                                    , storage=storage
                                    , booleans=booleans
                                    , percents=percents
                                    , operations=operations)

    def do_namespace_statistics(self, meta_stats, client, hosts, namespaces):
        counters = set([
            "available-bin-names"
            , "current-time"
            , "max-evicted-ttl"
            , "max-void-time"
            , "obj-size-hist-max"
        ])

        counts = set([
            "master-objects"
            , "master-sub-objects"
            , "non-expirable-objects"
            , "nsup-cycle-duration"
            , "objects"
            , "prole-objects"
            , "prole-sub-objects"
            , "repl-factor"
            , "sub-objects"
        ])

        storage = set([
            "data-used-bytes-memory"
            , "index-used-bytes-memory"
            , "sindex-used-bytes-memory"
            , "total-bytes-disk"
            , "total-bytes-memory"
            , "used-bytes-disk"
            , "used-bytes-memory"
        ])

        booleans = set([
            "hwm-breached"
            , "stop-writes"
        ])

        percents = set([
            "available_pct"
            , "cache-read-pct"
            , "free-pct-disk"
            , "free-pct-memory"
            , "nsup-cycle-sleep-pct"
        ])

        operations = set([
            "evicted-objects"
            , "expired-objects"
            , "ldt_deletes"
            , "ldt_delete_success"
            , "ldt_errors"
            , "ldt_reads"
            , "ldt_read_success"
            , "ldt_updates"
            , "ldt_writes"
            , "ldt_write_success"
            , "set-deleted-objects"
            , "set-evicted-objects"
        ])

        config = set([
            "max-write-cache"
            , "defrag-startup-minimum"
            , "ldt-page-size"
            , "high-water-memory-pct"
            , "memory-size"
            , "max-ttl"
            , "filesize"
            , "min-avail-pct"
            , "fsync-max-sec"
            , "default-ttl"
            , "cold-start-evict-ttl"
            , "defrag-sleep"
            , "write-smoothing-period"
            , "stop-writes-pct"
            , "defrag-queue-min"
            , "post-write-queue"
            , "high-water-disk-pct"
            , "writethreads"
            , "writecache"
            , "evict-tenths-pct"
            , "defrag-lwm-pct"
            , "flush-max-ms"
        ])

        for namespace in namespaces:
            command = "namespace/%s"%(namespace)
            try:
                _, (_, statistics) = client.info(command
                                                 , hosts=hosts).items()[0]
            except (TimeoutError, ClientError):
                collectd.warning('WARNING: TimeoutError executing info("%s")'%(command))
                meta_stats["timeouts"] += 1
                continue

            statistics = info_to_dict(statistics)

            self.process_statistics(meta_stats
                                    , statistics
                                    , "namespace.%s"%(namespace)
                                    , counters=counters
                                    , counts=counts
                                    , storage=storage
                                    , booleans=booleans
                                    , percents=percents
                                    , operations=operations
                                    , config=config)

    def do_dc_statistics(self, meta_stats, client, hosts, datacenters):
        counters = set([
           "xdr_dc_delete_ship_attempts"
           , "xdr_dc_rec_ship_attempts"
           , "xdr_dc_remote_ship_ok"
        ])
        counts = set([
           "xdr_dc_size"
           , "open_conn"
           , "xdr_dc_recs_shipping"
           , "xdr_dc_timelag"
           , "latency_avg_ship_ema"
           , "pool_conn"
        ])
        percents = set([
           "est_ship_compression_pct"
        ])
        booleans = set([
           "xdr_dc_state"
        ])
        storage = set([
           "esmt_byes_put_compressed"
        ])
        for dc in datacenters:
            command = "dc/%s"%(dc)
            try:
                _, (_, statistics) = client.info(command
                                                 , hosts=hosts).items()[0]
            except (TimeoutError, ClientError):
                collectd.warning('WARNING: TimeoutError executing info("%s")'%(command))
                meta_stats["timeouts"] += 1
                continue

            statistics = info_to_dict(statistics)

            self.process_statistics(meta_stats
                                    , statistics
                                    , "namespace.%s"%(namespace)
                                    , counters=counters
                                    , counts=counts
                                    , storage=storage
                                    , booleans=booleans
                                    , percents=percents)

    def do_latency_statistics(self, meta_stats, client, hosts):
        try:
            _, (_, tdata) = client.info("latency:", hosts=hosts).items()[0]
        except (TimeoutError, ClientError):
            collectd.warning('WARNING: TimeoutError executing info("latency:")')
            meta_stats["timeouts"] += 1
            return

        tdata = tdata.split(';')[:-1]
        while tdata != []:
            columns = tdata.pop(0)
            row = tdata.pop(0)

            hist_name, columns = columns.split(':', 1)
            columns = columns.split(',')
            row = row.split(',')

            # Get rid of duration data
            columns.pop(0)
            row.pop(0)
            row = [float(r) for r in row]

            # Don't need TPS column name
            columns.pop(0)
            tps_name = "%s_tps"%(hist_name)
            tps_value = row.pop(0)

            self.submit("count", tps_name, tps_value, "latency")

            while columns:
                name = "%s_pct%s"%(hist_name, columns.pop(0))
                name = name.replace(">", "_gt_")
                value = row.pop(0)
                self.submit("percent", name, value, "latency")

    def do_cluster_statistics(self, meta_stats, client, hosts):
      try:
        _, (_, tservices) = client.info("services", hosts=hosts).items()[0]
      except (TimeoutError, ClientError):
        collectd.warning('WARNING: TimeoutError executing info("services")')
        meta_stats["timeouts"] += 1

      try:
        _, (_, talumni) = client.info("services-alumni", hosts=hosts).items()[0]
      except (TimeoutError, ClientError):
        collectd.warning('WARNING: TimeoutError executing info("services-alumni")')
        meta_stats["timeouts"] += 1

      if tservices and talumni:
        services = tservices.split(";")
        alumni = talumni.split(";")

        self.submit("count", "services", len(services), "cluster")
        self.submit("count", "services-alumni", len(alumni), "cluster")

    def do_meta_statistics(self, meta_stats, context="meta"):
        for key, value in meta_stats.iteritems():
            name = "%s"%(key)
            if isinstance(value, dict):
                self.do_meta_statistics(value, context="%s.%s"%(context, name))
            else:
                self.submit("count", name, value, context)

    def get_all_statistics(self):
        collectd.debug("AEROSPIKE PLUGIN COLLECTING STATS")
        hosts = [(self.aerospike.host, self.aerospike.port)]
        policy = {"timeout": self.timeout}
        config = {"hosts":hosts, "policy":policy}

        meta_stats = {"timeouts": 0
                      , "unknown_metrics": 0}

        client = aerospike.client(config)
        try:
            if self.aerospike.user:
                client.connect(self.aerospike.user, self.aerospike.password)
            else:
                client.connect()
        except (TimeoutError, ClientError):
            collectd.warning('WARNING: ClientError unable to connect to Aerospike Node')
            self.submit("count", "connection_failure", 1, "meta", use_node_id=False)
            return
        else:
            self.submit("count", "connection_failure", 0, "meta", use_node_id=False)
            # Get this Nodes ID
            try:
                _, (_, node_id) = client.info("node", hosts=hosts).items()[0]
            except (TimeoutError, ClientError):
                collectd.warning('WARNING: TimeoutError executing info("node")')
                meta_stats["timeouts"] += 1
            else:
                self.node_id = node_id.strip()
                self.do_service_statistics(meta_stats, client, hosts)

                # Get list of namespaces
                try:
                    _, (_, namespaces) = client.info("namespaces"
                                                     , hosts=hosts).items()[0]
                except (TimeoutError, ClientError):
                    collectd.warning('WARNING: TimeoutError executing info("namespaces")')
                    meta_stats["timeouts"] += 1
                else:
                    namespaces = info_to_list(namespaces)
                    self.do_namespace_statistics(meta_stats, client
                                                 , hosts, namespaces)
                # Get list of XDR targets
                try:
                    _, (_, dc_info) = client.info("get-dc-config"
                                                     , hosts=hosts).items()[0]
                except (TimeoutError, ClientError):  
                    collectd.warning('WARNING: TimeoutError executing info("get-dc-config")')
                    meta_stats["timeouts"] += 1
                else:
                    if dc_info:
                        dcs = info_to_list(dc_info)
                        self.do_dc_statistics(meta_stats, client
                                                 , hosts, dcs)

                self.do_latency_statistics(meta_stats, client, hosts)

                self.do_cluster_statistics(meta_stats, client, hosts)
            finally:
                client.close()

        self.do_meta_statistics(meta_stats)

    def config(self, obj):
        for node in obj.children:
            if node.key == "Host":
                self.aerospike.host = node.values[0]
            elif node.key == "Port":
                self.aerospike.port = int(node.values[0])
            elif node.key == "User":
                self.aerospike.user = node.values[0]
            elif node.key == "Password":
                self.aerospike.password = node.values[0]
            elif node.key == "Timeout":
                self.timeout = int(node.values[0])
            elif node.key == "Prefix":
                self.prefix = node.values[0]
            elif node.key == "HostNameOverride":
                self.host_name = node.values[0]
            else:
                collectd.warning("%s: Unknown configuration key %s"%(
                    self.plugin_name
                    , node.key))

def info_to_dict(value, delimiter=';'):
    """
    Simple function to convert string to dict
    """

    stat_dict = {}
    stat_param = itertools.imap(lambda sp: info_to_tuple(sp, "="),
                                info_to_list(value, delimiter))
    for g in itertools.groupby(stat_param, lambda x: x[0]):
        try:
            value = [v[1] for v in g[1]]
            value = ",".join(sorted(value))
            stat_dict[g[0]] = value
        except:
            collectd.warning("WARNING: info_to_dict had problems parsing %s"%(
                value))
    return stat_dict

def info_colon_to_dict(value):
    """
    Simple function to convert colon separated string to dict
    """
    return info_to_dict(value, ':')

def info_to_list(value, delimiter=";"):
    return [s.strip() for s in re.split(delimiter, value)]

def info_to_tuple(value, delimiter=":"):
    return tuple(info_to_list(value, delimiter))

def info_to_dc_names(value):
    v = value.strip().split(';')
    return [ s.split(':')[0].split('=')[1] for s in v ]


as_plugin = AerospikePlugin()
collectd.register_read(as_plugin.get_all_statistics)
collectd.register_config(as_plugin.config)
