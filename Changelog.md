# CHANGELOG

- **0.0.5** - 07.10.2026 - Bug fix, maintenance
  - Fixed Wazuh Cluster always reporting "disabled": `GET /cluster/status` returns `data.enabled`, not `data.affected_items[0].enabled`
  - Wazuh Cluster: node name and type now come from `GET /cluster/local/info`
  - Fixed wazuh-db execution time metric (always 0)
  - Fixed crashes of Daemon, Agent and Syscheck checks when the manager clock runs ahead of the Checkmk server
  - Wazuh API: removed "Manager name" (the API does not provide it)
  - Fixed default scan age levels of the Wazuh Syscheck check: they did not validate against its ruleset
  - Added unit tests based on the Wazuh API spec
  - Moved the repository to checkmk-plugin-template (devcontainer for Checkmk 2.5, CI)
  - Code formatted with black/isort; flake8 findings fixed

- **0.0.4** - 26.11.2025 - Bug fix
  - Fixed agent summary parsing: API returns `data.connection.*` not `data.affected_items[0].*`

- **0.0.2** - 26.11.2025 - Extended monitoring capabilities
  - New services: Daemon Stats, Logs, Ruleset, Outdated Agents, Tasks
  - New piggyback services: SCA (Security Configuration Assessment), Syscheck
  - Added 40+ new metrics with graphs and perfometers
  - Added configurable thresholds for all new checks
  - Updated special agent with 8 new API endpoints
  - Added piggyback options for SCA and Syscheck data collection

- **0.0.1** - 26.11.2025 - First Version of special agent