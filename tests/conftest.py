import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

AGENT_PATH = Path(__file__).parent.parent / "plugins/wazuh/libexec/agent_wazuh"


@pytest.fixture(scope="session")
def agent():
    """The special agent script, imported as a module (it has no .py extension)."""
    loader = importlib.machinery.SourceFileLoader("agent_wazuh", str(AGENT_PATH))
    spec = importlib.util.spec_from_loader("agent_wazuh", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def parse_agent_output(text):
    """Split agent output into {(piggyback_host, section): string_table}.

    The main host is ''. All Wazuh sections use sep(0), so each line is one cell.
    """
    sections = {}
    host = ""
    current = None
    for line in text.splitlines():
        if line.startswith("<<<<") and line.endswith(">>>>"):
            host = line[4:-4]
            current = None
        elif line.startswith("<<<") and line.endswith(">>>"):
            name = line[3:-3].split(":")[0]
            current = sections.setdefault((host, name), [])
        elif current is not None:
            current.append([line])
    return sections


@pytest.fixture
def run_output(capsys):
    """Call an agent output function and return the parsed sections."""

    def _run(func, *args, **kwargs):
        func(*args, **kwargs)
        return parse_agent_output(capsys.readouterr().out)

    return _run


@pytest.fixture
def section_json(run_output):
    """Call an agent output function that writes one section and return its JSON."""

    def _run(func, *args, **kwargs):
        sections = run_output(func, *args, **kwargs)
        assert len(sections) == 1
        ((_key, string_table),) = sections.items()
        return json.loads(string_table[0][0])

    return _run
