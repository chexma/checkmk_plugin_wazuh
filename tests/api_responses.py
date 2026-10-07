"""Wazuh REST API responses, taken from the examples of the API spec v4.14.1.

Trimmed to the fields the special agent reads. Where the spec has no example
(analysisd, wazuh-db daemon stats), the response is built from its schema.
"""

API_INFO = {
    "data": {
        "title": "Wazuh API",
        "api_version": "4.14.1",
        "revision": "rc1",
        "hostname": "wazuh",
        "timestamp": "2019-04-02T08:08:11Z",
    },
    "error": 0,
}

MANAGER_INFO = {
    "data": {
        "affected_items": [
            {
                "path": "/var/ossec",
                "version": "v4.14.1",
                "type": "server",
                "max_agents": "unlimited",
                "openssl_support": True,
                "tz_offset": 0,
                "tz_name": "UTC",
                "uuid": "c842f85c-c24b-4b39-9508-093ce53482e7",
            }
        ],
        "total_affected_items": 1,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

MANAGER_STATUS = {
    "data": {
        "affected_items": [
            {
                "wazuh-agentlessd": "stopped",
                "wazuh-analysisd": "running",
                "wazuh-authd": "running",
                "wazuh-csyslogd": "stopped",
                "wazuh-dbd": "stopped",
                "wazuh-monitord": "running",
                "wazuh-execd": "running",
                "wazuh-integratord": "stopped",
                "wazuh-logcollector": "running",
                "wazuh-maild": "stopped",
                "wazuh-remoted": "running",
                "wazuh-reportd": "stopped",
                "wazuh-syscheckd": "running",
                "wazuh-clusterd": "running",
                "wazuh-modulesd": "running",
                "wazuh-db": "running",
                "wazuh-apid": "running",
            }
        ],
        "total_affected_items": 1,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

CLUSTER_STATUS = {"data": {"enabled": "yes", "running": "yes"}, "error": 0}

CLUSTER_STATUS_DISABLED = {"data": {"enabled": "no", "running": "no"}, "error": 0}

CLUSTER_HEALTHCHECK = {
    "data": {
        "affected_items": [
            {
                "info": {
                    "name": "master-node",
                    "type": "master",
                    "version": "4.4.0",
                    "ip": "wazuh-master",
                    "n_active_agents": 5,
                }
            },
            {
                "info": {
                    "name": "worker1",
                    "type": "worker",
                    "version": "4.4.0",
                    "ip": "172.21.0.7",
                    "n_active_agents": 3,
                },
                "status": {"sync_integrity_free": True, "sync_agent_info_free": True},
            },
            {
                "info": {
                    "name": "worker2",
                    "type": "worker",
                    "version": "4.4.0",
                    "ip": "172.21.0.6",
                    "n_active_agents": 1,
                },
                "status": {"sync_integrity_free": False, "sync_agent_info_free": True},
            },
        ],
        "total_affected_items": 3,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

AGENTS_SUMMARY = {
    "data": {
        "connection": {
            "active": 8,
            "disconnected": 0,
            "never_connected": 3,
            "pending": 0,
            "total": 11,
        },
        "configuration": {"synced": 8, "not_synced": 3, "total": 11},
    },
    "error": 0,
}

DAEMON_STATS = {
    "data": {
        "affected_items": [
            {
                "uptime": "2022-07-21 10:09:20+00:00",
                "timestamp": "2022-07-21 10:48:32+00:00",
                "name": "wazuh-remoted",
                "metrics": {
                    "bytes": {"received": 1000, "sent": 2000},
                    "queues": {"received": {"size": 131072, "usage": 0}},
                    "tcp_sessions": 4,
                },
            },
            {
                "uptime": "2022-07-21 10:09:20+00:00",
                "timestamp": "2022-07-21 10:48:32+00:00",
                "name": "wazuh-analysisd",
                "metrics": {
                    "events": {
                        "processed": 900,
                        "received": 1000,
                        "written_breakdown": {"alerts": 42, "archives": 0},
                    },
                    "queues": {
                        "alerts": {"size": 16384, "usage": 0},
                        "syscheck": {"size": 16384, "usage": 75},
                    },
                },
            },
            {
                "uptime": "2022-07-21 10:09:20+00:00",
                "timestamp": "2022-07-21 10:48:32+00:00",
                "name": "wazuh-db",
                "metrics": {
                    "queries": {"received": 5000, "received_breakdown": {"agent": 4000}},
                    "time": {"execution": 1234, "execution_breakdown": {"agent": 1000}},
                },
            },
        ],
        "total_affected_items": 3,
        "failed_items": [],
        "total_failed_items": 0,
    },
    "error": 0,
}

LOGS_SUMMARY = {
    "data": {
        "affected_items": [
            {
                "indexer-connector": {
                    "all": 24,
                    "info": 0,
                    "error": 0,
                    "critical": 0,
                    "warning": 24,
                    "debug": 0,
                }
            },
            {
                "wazuh-db": {
                    "info": 1,
                    "all": 4,
                    "critical": 0,
                    "debug": 0,
                    "error": 3,
                    "warning": 0,
                }
            },
            {
                "wazuh-remoted": {
                    "info": 744,
                    "all": 0,
                    "critical": 0,
                    "debug": 744,
                    "error": 0,
                    "warning": 0,
                }
            },
        ],
        "total_affected_items": 3,
        "failed_items": [],
        "total_failed_items": 0,
    },
    "error": 0,
}

RULES = {
    "data": {
        "affected_items": [{"filename": "0020-syslog_rules.xml", "id": 1001, "level": 2}],
        "total_affected_items": 4321,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

DECODERS = {
    "data": {
        "affected_items": [{"filename": "0005-wazuh_decoders.xml", "name": "wazuh"}],
        "total_affected_items": 987,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}


def _agent(agent_id, name, status, version="Wazuh v4.3.0"):
    return {
        "os": {
            "arch": "x86_64",
            "codename": "Focal Fossa",
            "major": "20",
            "minor": "04",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "version": "20.04.2 LTS",
        },
        "lastKeepAlive": "2021-05-26T12:40:40Z",
        "id": agent_id,
        "dateAdd": "2021-05-26 12:40:08+00:00",
        "configSum": "ab73af41699f13fdd81903b5f23d8d00",
        "manager": "wazuh-worker2",
        "group": ["default"],
        "registerIP": "any",
        "ip": "172.25.0.6",
        "name": name,
        "status": status,
        "mergedSum": "9a016508cea1e997ab8569f5cfab30f5",
        "version": version,
        "node_name": "worker2",
        "group_config_status": "synced",
        "status_code": 0,
    }


AGENTS_OUTDATED = {
    "data": {
        "affected_items": [
            _agent("001", "ac7cb188d538", "active", "Wazuh v3.0.0"),
            _agent("002", "91642a418627", "active", "Wazuh v3.0.0"),
        ],
        "total_affected_items": 2,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

AGENTS = {
    "data": {
        "affected_items": [
            _agent("000", "wazuh-manager", "active"),
            _agent("001", "Web_Server.01", "active"),
            _agent("002", "db01", "disconnected"),
        ],
        "total_affected_items": 3,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

TASKS = {
    "data": {
        "affected_items": [
            {
                "message": "Success",
                "agent": 2,
                "task_id": 1,
                "node": "worker2",
                "module": "upgrade_module",
                "command": "upgrade",
                "status": "In progress",
                "create_time": "2020-11-10 11:55:33+00:00",
                "update_time": "2020-11-10 11:55:36+00:00",
            },
            {
                "message": "Error",
                "agent": 3,
                "task_id": 2,
                "node": "worker2",
                "module": "upgrade_module",
                "command": "upgrade",
                "status": "Failed",
                "create_time": "2020-11-10 11:55:33+00:00",
                "update_time": "2020-11-10 11:56:36+00:00",
            },
        ],
        "total_affected_items": 2,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

SCA = {
    "data": {
        "affected_items": [
            {
                "fail": 87,
                "start_scan": "2022-09-27T08:07:02+00:00",
                "name": "CIS benchmark for Ubuntu Linux 20.04 LTS",
                "pass": 56,
                "score": 39,
                "end_scan": "2022-09-27T08:07:02+00:00",
                "policy_id": "cis_ubuntu20-04",
                "total_checks": 191,
                "invalid": 48,
            }
        ],
        "total_affected_items": 1,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

SYSCHECK_LAST_SCAN = {
    "data": {
        "affected_items": [{"start": "2021-05-28T12:11:33Z", "end": "2021-05-28T12:11:33Z"}],
        "total_affected_items": 1,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}

ROOTCHECK_LAST_SCAN = {
    "data": {
        "affected_items": [{"start": "2021-05-28T12:10:00Z", "end": "2021-05-28T12:11:00Z"}],
        "total_affected_items": 1,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "error": 0,
}
