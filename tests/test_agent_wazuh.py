"""Special agent: API responses (shaped like the API spec) to agent sections."""

import json

import api_responses as api
import pytest


def test_api_section(agent, section_json):
    data = section_json(agent.output_api_section, api.API_INFO, api.MANAGER_INFO)
    assert data["api_version"] == "4.14.1"
    assert "manager_name" not in data  # GET /manager/info has no name
    assert data["hostname"] == "wazuh"
    assert data["manager_version"] == "v4.14.1"
    assert data["manager_type"] == "server"
    assert data["manager_path"] == "/var/ossec"
    assert data["manager_tz_name"] == "UTC"


def test_manager_section(agent, section_json):
    data = section_json(agent.output_manager_section, api.MANAGER_STATUS)
    assert data["wazuh-analysisd"] == "running"
    assert data["wazuh-maild"] == "stopped"


def test_cluster_section_disabled(agent, section_json):
    data = section_json(agent.output_cluster_section, api.CLUSTER_STATUS_DISABLED, None, None)
    assert data["enabled"] is False
    assert data["running"] is False


def test_cluster_section_running(agent, section_json):
    data = section_json(
        agent.output_cluster_section,
        api.CLUSTER_STATUS,
        api.CLUSTER_HEALTHCHECK,
        api.CLUSTER_LOCAL_INFO,
    )
    assert data["enabled"] is True
    assert data["running"] is True
    assert data["node_name"] == "master-node"
    assert data["node_type"] == "master"
    assert [n["name"] for n in data["nodes"]] == ["master-node", "worker1", "worker2"]


def test_agents_summary_section(agent, section_json):
    data = section_json(agent.output_agents_summary_section, api.AGENTS_SUMMARY)
    assert data == {
        "active": 8,
        "disconnected": 0,
        "never_connected": 3,
        "pending": 0,
        "total": 11,
    }


def test_daemon_stats_section(agent, section_json):
    data = section_json(agent.output_daemon_stats_section, api.DAEMON_STATS)
    assert set(data) == {"wazuh-remoted", "wazuh-analysisd", "wazuh-db"}
    assert data["wazuh-remoted"]["uptime"] == "2022-07-21 10:09:20+00:00"
    assert data["wazuh-remoted"]["metrics"]["tcp_sessions"] == 4


def test_logs_section(agent, section_json):
    data = section_json(agent.output_logs_section, api.LOGS_SUMMARY)
    assert data["totals"]["error"] == 3
    assert data["totals"]["warning"] == 24
    assert data["totals"]["critical"] == 0
    assert set(data["components"]) == {"indexer-connector", "wazuh-db", "wazuh-remoted"}


def test_ruleset_section(agent, section_json):
    data = section_json(agent.output_ruleset_section, api.RULES, api.DECODERS)
    assert data == {"rules_total": 4321, "decoders_total": 987}


def test_outdated_section(agent, section_json):
    data = section_json(agent.output_outdated_section, api.AGENTS_OUTDATED)
    assert data["total"] == 2
    assert data["agents"][0] == {"id": "001", "name": "ac7cb188d538", "version": "Wazuh v3.0.0"}


def test_tasks_section(agent, section_json):
    data = section_json(agent.output_tasks_section, api.TASKS)
    assert data["total"] == 2
    assert data["by_status"] == {"In progress": 1, "Failed": 1}


@pytest.mark.parametrize(
    "name, expected",
    [
        ("Web_Server.01", "web-server-01"),
        ("--a__b--", "a-b"),
        ("x" * 70, "x" * 63),
    ],
)
def test_sanitize_hostname(agent, name, expected):
    assert agent.sanitize_hostname(name) == expected


class FakeClient:
    def get_agent_sca(self, agent_id):
        return api.SCA

    def get_agent_syscheck_last_scan(self, agent_id):
        return api.SYSCHECK_LAST_SCAN

    def get_agent_rootcheck_last_scan(self, agent_id):
        return api.ROOTCHECK_LAST_SCAN


def test_piggyback_only_non_active_agents(agent, run_output):
    sections = run_output(agent.output_agents_piggyback, FakeClient(), api.AGENTS)
    assert set(sections) == {("db01", "wazuh_agent")}


def test_piggyback_all_agents_with_sca_and_syscheck(agent, run_output):
    sections = run_output(
        agent.output_agents_piggyback,
        FakeClient(),
        api.AGENTS,
        include_active=True,
        include_sca=True,
        include_syscheck=True,
    )
    # The manager (000) is skipped; SCA and syscheck only for active agents
    assert set(sections) == {
        ("web-server-01", "wazuh_agent"),
        ("web-server-01", "wazuh_sca"),
        ("web-server-01", "wazuh_syscheck"),
        ("web-server-01", "wazuh_rootcheck"),
        ("db01", "wazuh_agent"),
    }


class FakeAPIClient(FakeClient):
    """Replaces WazuhAPIClient in main(); answers every call with the spec examples."""

    def __init__(self, **kwargs):
        pass

    get_api_info = staticmethod(lambda: api.API_INFO)
    get_manager_info = staticmethod(lambda: api.MANAGER_INFO)
    get_manager_status = staticmethod(lambda: api.MANAGER_STATUS)
    get_cluster_status = staticmethod(lambda: api.CLUSTER_STATUS)
    get_cluster_health = staticmethod(lambda: api.CLUSTER_HEALTHCHECK)
    get_cluster_local_info = staticmethod(lambda: api.CLUSTER_LOCAL_INFO)
    get_agents_summary = staticmethod(lambda: api.AGENTS_SUMMARY)
    get_overview_agents = staticmethod(lambda: {})
    get_daemon_stats = staticmethod(lambda: api.DAEMON_STATS)
    get_logs_summary = staticmethod(lambda: api.LOGS_SUMMARY)
    get_rules_summary = staticmethod(lambda: api.RULES)
    get_decoders_summary = staticmethod(lambda: api.DECODERS)
    get_agents_outdated = staticmethod(lambda: api.AGENTS_OUTDATED)
    get_tasks = staticmethod(lambda: api.TASKS)
    get_agents = staticmethod(lambda: api.AGENTS)


def test_main(agent, run_output, monkeypatch):
    monkeypatch.setattr(agent, "WazuhAPIClient", FakeAPIClient)
    monkeypatch.setattr(
        "sys.argv",
        ["agent_wazuh", "--hostname", "wazuh", "--password", "x", "--piggyback-agents"],
    )
    sections = run_output(agent.main)
    assert {name for host, name in sections if host == ""} == {
        "wazuh_api",
        "wazuh_manager",
        "wazuh_cluster",
        "wazuh_agents",
        "wazuh_daemon_stats",
        "wazuh_logs",
        "wazuh_ruleset",
        "wazuh_agents_outdated",
        "wazuh_tasks",
    }
    cluster = json.loads(sections[("", "wazuh_cluster")][0][0])
    assert cluster["running"] is True
    assert len(cluster["nodes"]) == 3
    assert ("db01", "wazuh_agent") in sections
