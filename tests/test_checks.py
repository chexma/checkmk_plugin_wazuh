"""Check plugins: agent sections (built by the special agent from API responses) to results."""

import json
from datetime import datetime

import api_responses as api
import pytest
from cmk.agent_based.v2 import Metric, Result, Service, State
from cmk_addons.plugins.wazuh.agent_based import (
    wazuh_agent,
    wazuh_agents,
    wazuh_agents_outdated,
    wazuh_api,
    wazuh_cluster,
    wazuh_daemon_stats,
    wazuh_logs,
    wazuh_manager,
    wazuh_ruleset,
    wazuh_sca,
    wazuh_syscheck,
    wazuh_tasks,
)

NOW = datetime.fromisoformat("2021-05-28T13:11:33+00:00").timestamp()


@pytest.fixture
def section(run_output):
    """Run an agent output function and parse the section with the plugin's parse function."""

    def _section(parse, func, *args, **kwargs):
        sections = run_output(func, *args, **kwargs)
        ((_key, string_table),) = sections.items()
        return parse(string_table)

    return _section


def _defaults(plugin):
    return dict(plugin.check_default_parameters or {})


def _state(results):
    return State.worst(*(r.state for r in results if isinstance(r, Result)))


def _summaries(results):
    return [r.summary for r in results if isinstance(r, Result) and r.summary]


def _metrics(results):
    return {m.name: m.value for m in results if isinstance(m, Metric)}


def _section_of(data):
    return [[json.dumps(data)]]


@pytest.mark.parametrize(
    "parse",
    [
        wazuh_api.parse_wazuh_api,
        wazuh_manager.parse_wazuh_manager,
        wazuh_cluster.parse_wazuh_cluster,
        wazuh_agents.parse_wazuh_agents,
        wazuh_daemon_stats.parse_wazuh_daemon_stats,
        wazuh_logs.parse_wazuh_logs,
        wazuh_ruleset.parse_wazuh_ruleset,
        wazuh_agents_outdated.parse_wazuh_agents_outdated,
        wazuh_tasks.parse_wazuh_tasks,
        wazuh_agent.parse_wazuh_agent,
        wazuh_sca.parse_wazuh_sca,
        wazuh_syscheck.parse_wazuh_syscheck,
    ],
)
def test_parse_empty_or_broken(parse):
    assert parse([]) is None
    assert parse([["{not json"]]) is None


# ---------------------------------------------------------------- Wazuh API


def test_api(agent, section):
    sec = section(
        wazuh_api.parse_wazuh_api, agent.output_api_section, api.API_INFO, api.MANAGER_INFO
    )
    assert list(wazuh_api.discover_wazuh_api(sec)) == [Service()]
    results = list(wazuh_api.check_wazuh_api(sec))
    assert _state(results) is State.OK
    assert _summaries(results)[:2] == ["API v4.14.1, Manager vv4.14.1", "Host: wazuh"]


# ---------------------------------------------------------------- Wazuh Manager


def test_manager_all_required_running(agent, section):
    sec = section(
        wazuh_manager.parse_wazuh_manager, agent.output_manager_section, api.MANAGER_STATUS
    )
    results = list(
        wazuh_manager.check_wazuh_manager(_defaults(wazuh_manager.check_plugin_wazuh_manager), sec)
    )
    assert _state(results) is State.OK
    assert _summaries(results) == ["11 processes running"]


def test_manager_required_stopped():
    sec = {"wazuh-analysisd": "stopped", "wazuh-db": "running", "wazuh-maild": "stopped"}
    results = list(
        wazuh_manager.check_wazuh_manager(_defaults(wazuh_manager.check_plugin_wazuh_manager), sec)
    )
    assert _state(results) is State.CRIT
    assert "Stopped required: wazuh-analysisd" in _summaries(results)


def test_manager_custom_required_processes():
    sec = {"wazuh-analysisd": "stopped", "wazuh-maild": "stopped"}
    results = list(wazuh_manager.check_wazuh_manager({"required_processes": ["wazuh-maild"]}, sec))
    assert "Stopped required: wazuh-maild" in _summaries(results)


# ---------------------------------------------------------------- Wazuh Cluster


def test_cluster_disabled(agent, section):
    sec = section(
        wazuh_cluster.parse_wazuh_cluster,
        agent.output_cluster_section,
        api.CLUSTER_STATUS_DISABLED,
        None,
        None,
    )
    results = list(wazuh_cluster.check_wazuh_cluster({"sync_status": "warn"}, sec))
    assert _state(results) is State.OK
    assert _summaries(results)[0] == "Cluster disabled (single-node mode)"


def test_cluster_running_from_api(agent, section):
    sec = section(
        wazuh_cluster.parse_wazuh_cluster,
        agent.output_cluster_section,
        api.CLUSTER_STATUS,
        api.CLUSTER_HEALTHCHECK,
        api.CLUSTER_LOCAL_INFO,
    )
    results = list(wazuh_cluster.check_wazuh_cluster({"sync_status": "warn"}, sec))
    # worker2 has an integrity sync in progress
    assert _state(results) is State.WARN
    assert _summaries(results)[:3] == [
        "Cluster running",
        "This node: master-node (master)",
        "3 node(s) in cluster",
    ]
    assert _metrics(results) == {"wazuh_cluster_nodes": 3, "wazuh_cluster_active_agents": 9}


CLUSTER_SECTION = {
    "enabled": True,
    "running": True,
    "node_name": "master-node",
    "node_type": "master",
    "nodes": [
        {"name": "master-node", "n_active_agents": 5},
        {"name": "worker1", "n_active_agents": 3, "sync_integrity_free": False},
    ],
}


@pytest.mark.parametrize(
    "sync_status, expected",
    [("warn", State.WARN), ("crit", State.CRIT), ("ignore", State.OK)],
)
def test_cluster_sync_issues(sync_status, expected):
    results = list(wazuh_cluster.check_wazuh_cluster({"sync_status": sync_status}, CLUSTER_SECTION))
    assert _state(results) is expected
    assert _metrics(results) == {"wazuh_cluster_nodes": 2, "wazuh_cluster_active_agents": 8}


def test_cluster_too_few_nodes():
    results = list(
        wazuh_cluster.check_wazuh_cluster(
            {"sync_status": "ignore", "expected_nodes": 3}, CLUSTER_SECTION
        )
    )
    assert _state(results) is State.WARN
    assert "Only 2/3 nodes available" in _summaries(results)


def test_cluster_enabled_not_running():
    sec = {"enabled": True, "running": False, "node_name": "n", "node_type": "master"}
    results = list(wazuh_cluster.check_wazuh_cluster({"sync_status": "warn"}, sec))
    assert _state(results) is State.CRIT


# ---------------------------------------------------------------- Wazuh Agents


def test_agents_summary(agent, section):
    sec = section(
        wazuh_agents.parse_wazuh_agents, agent.output_agents_summary_section, api.AGENTS_SUMMARY
    )
    results = list(
        wazuh_agents.check_wazuh_agents(_defaults(wazuh_agents.check_plugin_wazuh_agents), sec)
    )
    assert _summaries(results)[0] == "Total: 11, Active: 8"
    # 3 never connected agents: below the default levels (5, 10)
    assert _state(results) is State.OK
    assert _metrics(results)["wazuh_agents_never_connected"] == 3


def test_agents_disconnected_levels():
    sec = {"active": 5, "disconnected": 5, "never_connected": 0, "pending": 0, "total": 10}
    results = list(
        wazuh_agents.check_wazuh_agents(_defaults(wazuh_agents.check_plugin_wazuh_agents), sec)
    )
    assert _state(results) is State.CRIT
    assert _metrics(results)["wazuh_agents_disconnected_pct"] == 50.0


def test_agents_no_agents():
    sec = {"active": 0, "disconnected": 0, "never_connected": 0, "pending": 0, "total": 0}
    results = list(
        wazuh_agents.check_wazuh_agents(_defaults(wazuh_agents.check_plugin_wazuh_agents), sec)
    )
    assert _state(results) is State.OK


# ---------------------------------------------------------------- Wazuh Daemon stats


@pytest.fixture
def daemon_section(agent, section, monkeypatch):
    now = datetime.fromisoformat("2022-07-21 10:48:32+00:00").timestamp()
    monkeypatch.setattr(wazuh_daemon_stats.time, "time", lambda: now)
    return section(
        wazuh_daemon_stats.parse_wazuh_daemon_stats,
        agent.output_daemon_stats_section,
        api.DAEMON_STATS,
    )


def _daemon_params():
    return _defaults(wazuh_daemon_stats.check_plugin_wazuh_daemon_stats)


def test_daemon_discovery(daemon_section):
    assert {s.item for s in wazuh_daemon_stats.discover_wazuh_daemon_stats(daemon_section)} == {
        "wazuh-remoted",
        "wazuh-analysisd",
        "wazuh-db",
    }


def test_daemon_remoted(daemon_section):
    results = list(
        wazuh_daemon_stats.check_wazuh_daemon_stats(
            "wazuh-remoted", _daemon_params(), daemon_section
        )
    )
    assert _state(results) is State.OK
    assert "TCP sessions: 4" in _summaries(results)
    metrics = _metrics(results)
    assert metrics["wazuh_remoted_bytes_received"] == 1000
    assert metrics["wazuh_remoted_bytes_sent"] == 2000
    assert metrics["wazuh_wazuh_remoted_uptime"] > 0


def test_daemon_analysisd_max_queue_usage(daemon_section):
    results = list(
        wazuh_daemon_stats.check_wazuh_daemon_stats(
            "wazuh-analysisd", _daemon_params(), daemon_section
        )
    )
    # syscheck queue at 75 %: above the default WARN level of 70 %
    assert _state(results) is State.WARN
    assert "Events: 1000 received, 900 processed" in _summaries(results)
    assert _metrics(results)["wazuh_analysisd_alerts_written"] == 42


def test_daemon_db(daemon_section):
    results = list(
        wazuh_daemon_stats.check_wazuh_daemon_stats("wazuh-db", _daemon_params(), daemon_section)
    )
    assert "Queries: 5000" in _summaries(results)


def test_daemon_db_execution_time(daemon_section):
    results = list(
        wazuh_daemon_stats.check_wazuh_daemon_stats("wazuh-db", _daemon_params(), daemon_section)
    )
    assert _metrics(results)["wazuh_db_execution_time"] == 1234


def test_daemon_clock_skew(daemon_section, monkeypatch):
    uptime = datetime.fromisoformat("2022-07-21 10:09:20+00:00").timestamp()
    monkeypatch.setattr(wazuh_daemon_stats.time, "time", lambda: uptime - 60)
    results = list(
        wazuh_daemon_stats.check_wazuh_daemon_stats("wazuh-db", _daemon_params(), daemon_section)
    )
    assert "Uptime: 0 seconds" in _summaries(results)


def test_daemon_missing(daemon_section):
    results = list(
        wazuh_daemon_stats.check_wazuh_daemon_stats("wazuh-foo", _daemon_params(), daemon_section)
    )
    assert _state(results) is State.UNKNOWN


# ---------------------------------------------------------------- Wazuh Logs


def test_logs(agent, section):
    sec = section(wazuh_logs.parse_wazuh_logs, agent.output_logs_section, api.LOGS_SUMMARY)
    results = list(wazuh_logs.check_wazuh_logs(_defaults(wazuh_logs.check_plugin_wazuh_logs), sec))
    # 3 errors: WARN (1, 10); 24 warnings: WARN (10, 50)
    assert _state(results) is State.WARN
    assert _metrics(results) == {
        "wazuh_log_errors": 3,
        "wazuh_log_warnings": 24,
        "wazuh_log_critical": 0,
        "wazuh_log_info": 745,
    }


def test_logs_critical():
    sec = {"totals": {"critical": 1}, "components": {}}
    results = list(wazuh_logs.check_wazuh_logs(_defaults(wazuh_logs.check_plugin_wazuh_logs), sec))
    assert _state(results) is State.CRIT


# ---------------------------------------------------------------- Wazuh Ruleset


def test_ruleset(agent, section):
    sec = section(
        wazuh_ruleset.parse_wazuh_ruleset, agent.output_ruleset_section, api.RULES, api.DECODERS
    )
    results = list(wazuh_ruleset.check_wazuh_ruleset({}, sec))
    assert _state(results) is State.OK
    assert _summaries(results) == ["Rules: 4321, Decoders: 987"]


def test_ruleset_below_minimum():
    sec = {"rules_total": 10, "decoders_total": 10}
    results = list(wazuh_ruleset.check_wazuh_ruleset({"min_rules": 100, "min_decoders": 5}, sec))
    assert _state(results) is State.WARN
    assert "Rules below minimum (10 < 100)" in _summaries(results)


# ---------------------------------------------------------------- Wazuh Agents Outdated


def test_agents_outdated(agent, section):
    sec = section(
        wazuh_agents_outdated.parse_wazuh_agents_outdated,
        agent.output_outdated_section,
        api.AGENTS_OUTDATED,
    )
    results = list(
        wazuh_agents_outdated.check_wazuh_agents_outdated(
            _defaults(wazuh_agents_outdated.check_plugin_wazuh_agents_outdated), sec
        )
    )
    # 2 outdated agents: WARN (1, 5)
    assert _state(results) is State.WARN
    notices = [r.details for r in results if isinstance(r, Result)]
    assert "Outdated: ac7cb188d538 (Wazuh v3.0.0), 91642a418627 (Wazuh v3.0.0)" in notices


# ---------------------------------------------------------------- Wazuh Tasks


def test_tasks(agent, section):
    sec = section(wazuh_tasks.parse_wazuh_tasks, agent.output_tasks_section, api.TASKS)
    results = list(
        wazuh_tasks.check_wazuh_tasks(_defaults(wazuh_tasks.check_plugin_wazuh_tasks), sec)
    )
    # 1 failed task: WARN (1, 5)
    assert _state(results) is State.WARN
    assert _metrics(results)["wazuh_tasks_in_progress"] == 1
    assert _metrics(results)["wazuh_tasks_failed"] == 1


def test_tasks_none():
    results = list(wazuh_tasks.check_wazuh_tasks({}, {"total": 0, "by_status": {}}))
    assert _summaries(results) == ["No tasks"]


# ---------------------------------------------------------------- Piggyback


@pytest.fixture
def piggyback(agent, run_output):
    from test_agent_wazuh import FakeClient

    return run_output(
        agent.output_agents_piggyback,
        FakeClient(),
        api.AGENTS,
        include_active=True,
        include_sca=True,
        include_syscheck=True,
    )


def test_agent_active(piggyback, monkeypatch):
    monkeypatch.setattr(wazuh_agent.time, "time", lambda: NOW)
    sec = wazuh_agent.parse_wazuh_agent(piggyback[("web-server-01", "wazuh_agent")])
    labels = {(lbl.name, lbl.value) for lbl in wazuh_agent.host_label_wazuh_agent(sec)}
    assert labels == {
        ("cmk/wazuh_agent", "yes"),
        ("cmk/os_platform", "ubuntu"),
        ("cmk/os_name", "Ubuntu"),
        ("wazuh/group/default", "yes"),
    }
    params = _defaults(wazuh_agent.check_plugin_wazuh_agent)
    results = list(wazuh_agent.check_wazuh_agent(params, sec))
    # last keepalive 2 days ago: CRIT (1 h, 24 h)
    assert _state(results) is State.CRIT
    assert _summaries(results)[:2] == ["Status: active", "Version: Wazuh v4.3.0"]


@pytest.mark.parametrize("setting, expected", [("warn", State.WARN), ("crit", State.CRIT)])
def test_agent_disconnected(piggyback, setting, expected):
    sec = wazuh_agent.parse_wazuh_agent(piggyback[("db01", "wazuh_agent")])
    sec["last_keepalive"] = ""
    results = list(wazuh_agent.check_wazuh_agent({"disconnected_state": setting}, sec))
    assert _state(results) is expected


def test_agent_keepalive_clock_skew(piggyback, monkeypatch):
    keepalive = datetime.fromisoformat("2021-05-26T12:40:40+00:00").timestamp()
    monkeypatch.setattr(wazuh_agent.time, "time", lambda: keepalive - 60)
    sec = wazuh_agent.parse_wazuh_agent(piggyback[("web-server-01", "wazuh_agent")])
    results = list(
        wazuh_agent.check_wazuh_agent(_defaults(wazuh_agent.check_plugin_wazuh_agent), sec)
    )
    assert _state(results) is State.OK


def test_sca(piggyback):
    sec = wazuh_sca.parse_wazuh_sca(piggyback[("web-server-01", "wazuh_sca")])
    assert [s.item for s in wazuh_sca.discover_wazuh_sca(sec)] == ["cis_ubuntu20-04"]
    results = list(
        wazuh_sca.check_wazuh_sca(
            "cis_ubuntu20-04", _defaults(wazuh_sca.check_plugin_wazuh_sca), sec
        )
    )
    # score 39 %: CRIT below 50 %; 87 failed: CRIT (10, 25)
    assert _state(results) is State.CRIT
    assert _summaries(results)[0] == "CIS benchmark for Ubuntu Linux 20.04 LTS: Score 39%"
    assert _metrics(results)["wazuh_sca_total"] == 191


def test_sca_policy_missing(piggyback):
    sec = wazuh_sca.parse_wazuh_sca(piggyback[("web-server-01", "wazuh_sca")])
    results = list(wazuh_sca.check_wazuh_sca("foo", {}, sec))
    assert _state(results) is State.UNKNOWN


@pytest.mark.parametrize(
    "age, expected",
    [(3600, State.OK), (90000, State.WARN), (200000, State.CRIT)],
)
def test_syscheck_age(piggyback, monkeypatch, age, expected):
    sec = wazuh_syscheck.parse_wazuh_syscheck(piggyback[("web-server-01", "wazuh_syscheck")])
    end = datetime.fromisoformat("2021-05-28T12:11:33+00:00").timestamp()
    monkeypatch.setattr(wazuh_syscheck.time, "time", lambda: end + age)
    results = list(
        wazuh_syscheck.check_wazuh_syscheck(
            _defaults(wazuh_syscheck.check_plugin_wazuh_syscheck), sec
        )
    )
    assert _state(results) is expected


def test_syscheck_clock_skew(piggyback, monkeypatch):
    sec = wazuh_syscheck.parse_wazuh_syscheck(piggyback[("web-server-01", "wazuh_syscheck")])
    end = datetime.fromisoformat("2021-05-28T12:11:33+00:00").timestamp()
    monkeypatch.setattr(wazuh_syscheck.time, "time", lambda: end - 60)
    results = list(wazuh_syscheck.check_wazuh_syscheck({}, sec))
    assert _state(results) is State.OK


def test_syscheck_in_progress():
    sec = {"start": "2021-05-28T12:11:33Z", "end": None}
    results = list(wazuh_syscheck.check_wazuh_syscheck({}, sec))
    assert _summaries(results) == ["Scan in progress"]


def test_syscheck_never_completed():
    results = list(wazuh_syscheck.check_wazuh_syscheck({}, {"start": None, "end": None}))
    assert _state(results) is State.WARN
