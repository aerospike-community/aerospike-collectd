import aerospike as aerospike_client
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
        self.aerospike = Data()
        self.aerospike.host = "127.0.0.1"
        self.aerospike.port = 3000
        self.aerospike.user = None
        self.aerospike.password = None
        self.node_id = None
        self.timeout = 2000

    def submit(self, value_type, instance, value, namespace=None):
        plugin_instance = []
        if self.prefix:
            plugin_instance.append(self.prefix)

        plugin_instance.append(self.node_id)

        if namespace:
            plugin_instance.append("namespace")
            plugin_instance.append(namespace)

        plugin_instance = ".".join(plugin_instance)

        data = pprint.pformat((type, plugin_instance, instance
                               , value, namespace))
        collectd.debug("Dispatching: %s"%(data))

        val = collectd.Values()
        val.plugin = self.plugin_name
        val.plugin_instance = plugin_instance
        val.type = value_type
        val.type_instance = instance.lower().replace('-', '_')
        # HACK with this dummy dict in place JSON parsing works
        # https://github.com/collectd/collectd/issues/716
        val.meta = {'0': True}
        val.values = [value, ]
        val.dispatch()

    def process_statistics(self, statistics, counters=None, counts=None
                           , storage=None, booleans=None, percents=None
                           , operations=None, namespace=None):

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

        for key, value in statistics.iteritems():
            if key in counters:
                value_type = "counter"
            elif key in counts:
                value_type = "count"
            elif key in booleans:
                value_type = "boolean"
                value = value.lower()
                if value == "false" or value == "no" or value == "0":
                    value = 0
                else:
                    value = 1
            elif key in percents:
                value_type = "percent"
            elif key in storage:
                value_type = "storage"
            elif key in operations:
                value_type = "operation"
            else:
                # not in any group, skip
                continue

            self.submit(value_type, key, value, namespace)

    def do_service_statistics(self, client, hosts):
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
            , "used-bytes-disk"
            , "used-bytes-memory"
        ])

        operations = set([
            "batch_errors"
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
            , "query_long_running"
            , "query_lookup_abort"
            , "query_lookup_avg_rec_count"
            , "query_lookup_err"
            , "query_lookups"
            , "query_lookup_success"
            , "query_reqs"
            , "query_short_queue_full"
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

        unused = set([
            "total-bytes-disk"
            , "total-bytes-memory"
        ])

        _, (_, statistics) = client.info("statistics", hosts=hosts).items()[0]
        statistics = info_to_dict(statistics)
        self.process_statistics(statistics
                                , counters=counters
                                , counts=counts
                                , storage=storage
                                , booleans=booleans
                                , percents=percents
                                , operations=operations)

    def do_namespace_statistics(self, client, hosts, namespaces):
        counters = set([
            "available-bin-names"
            , "current-time"
            , "max-evicted-ttl"
            , "max-void-time"
            , "obj-size-hist-max"
        ])

        counts = set([
            "data-used-bytes-memory"
            , "master-objects"
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
            "index-used-bytes-memory"
            , "sindex-used-bytes-memory"
            , "used-bytes-disk"
            , "used-bytes-memory"
        ])

        booleans = set([
            "hwm-breached"
            , "stop-writes"
        ])

        percents = set([
            "available_pct"
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

        for namespace in namespaces:
            _, (_, statistics) = client.info("namespace/%s"%(namespace)
                                             , hosts=hosts).items()[0]
            statistics = info_to_dict(statistics)

            self.process_statistics(statistics
                                    , counters=counters
                                    , counts=counts
                                    , storage=storage
                                    , booleans=booleans
                                    , percents=percents
                                    , operations=operations
                                    , namespace=namespace)

    def do_latency_statistics(self, client, hosts):
        _, (_, tdata) = client.info("latency:", hosts=hosts).items()[0]
        tdata = tdata.split(';')[:-1]
        data = {}
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

            self.submit("count", tps_name, tps_value)

            while columns:
                name = "%s_pct%s"%(hist_name, columns.pop(0))
                name = name.replace(">", "_gt_")
                value = row.pop(0)
                self.submit("percent", name, value)

    def get_all_statistics(self):
        collectd.debug("AEROSPIKE PLUGIN COLLECTING STATS")
        hosts = [(self.aerospike.host, self.aerospike.port)]
        policy = {"timeout": self.timeout}
        config = {"hosts":hosts, "policy":policy}
        client = aerospike_client.client(config).connect()

        # Get this Nodes ID
        _, (_, node_id) = client.info("node", hosts=hosts).items()[0]
        self.node_id = node_id.strip()
        self.do_service_statistics(client, hosts)

        # Get list of namespaces
        _, (_, namespaces) = client.info("namespaces", hosts=hosts).items()[0]
        namespaces = info_to_list(namespaces)

        self.do_namespace_statistics(client, hosts, namespaces)
        self.do_latency_statistics(client, hosts)

        client.close()

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
            else:
                collectd.warning("%s: Unknown configuration key %s"%(
                    self.plugin_name
                    , node.key))

def info_to_dict(value, delimiter = ';'):
    """
    Simple function to convert string to dict
    """

    stat_dict = {}
    stat_param = itertools.imap(lambda sp: info_to_tuple(sp, "="),
                                info_to_list(value, delimiter))
    for g in itertools.groupby(stat_param, lambda x: x[0]):
        try:
            value = map(lambda v: v[1], g[1])
            value = ",".join(sorted(value)) if len(value) > 1 else value[0]
            stat_dict[g[0]] = value
        except:
            # NOTE: 3.0 had a bug in stats at least prior to 3.0.44. This will
            # ignore that bug.

            # Not sure if this bug is fixed or not.. removing this try/catch
            # results in things not working. TODO: investigate.
            pass
    return stat_dict

def info_colon_to_dict(value):
    """
    Simple function to convert colon separated string to dict
    """
    return info_to_dict(value, ':')

def info_to_list(value, delimiter = ";"):
    return [s.strip() for s in re.split(delimiter, value)]

def info_to_tuple(value, delimiter = ":"):
    return tuple(info_to_list(value, delimiter))

as_plugin = AerospikePlugin()
collectd.register_read(as_plugin.get_all_statistics)
collectd.register_config(as_plugin.config)
