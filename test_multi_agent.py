"""Tests for MultiAgentCoordinator module."""
import pytest
from agents.multi_agent import MultiAgentCoordinator, AgentResult

@pytest.fixture
def coordinator():
    return MultiAgentCoordinator()

def test_coordinator_init(coordinator):
    """Test MultiAgentCoordinator initializes correctly."""
    assert coordinator is not None
    assert coordinator.agents == []

def test_agent_result_init():
    """Test AgentResult initializes correctly."""
    result = {"detected": True, "confidence": "high", "score": 0.85, "z_outlier": 2.5}
    agent_result = AgentResult(
        agent_id="test-001",
        host="localhost",
        mode="endpoint",
        result=result,
        mitre_ttp="T1573.002",
        duration=1.0
    )
    assert agent_result.agent_id == "test-001"
    assert agent_result.host == "localhost"
    assert agent_result.mode == "endpoint"
    assert agent_result.mitre_ttp == "T1573.002"

def test_agent_result_to_dict():
    """Test AgentResult to_dict method."""
    result = {"detected": True, "confidence": "high", "score": 0.85, "z_outlier": 2.5}
    agent_result = AgentResult(
        agent_id="test-001",
        host="localhost",
        mode="endpoint",
        result=result,
        mitre_ttp="T1573.002",
        duration=1.0
    )
    d = agent_result.to_dict()
    assert isinstance(d, dict)
    assert d["agent_id"] == "test-001"
    assert d["detected"] == True
    assert "timestamp" in d

def test_coordinator_add_agent(coordinator):
    """Test adding an agent to coordinator."""
    agent = {"name": "test_agent", "type": "endpoint"}
    coordinator.agents.append(agent)
    assert len(coordinator.agents) == 1

def test_coordinator_multiple_agents(coordinator):
    """Test adding multiple agents."""
    coordinator.agents.append({"name": "agent1"})
    coordinator.agents.append({"name": "agent2"})
    assert len(coordinator.agents) == 2

def test_coordinator_remove_agent(coordinator):
    """Test removing an agent."""
    coordinator.agents.append({"name": "test_agent"})
    coordinator.agents.remove({"name": "test_agent"})
    assert len(coordinator.agents) == 0

def test_agent_result_with_different_modes():
    """Test AgentResult with different modes."""
    result = {"detected": False, "confidence": "low", "score": 0.2, "z_outlier": 0.5}
    for mode in ["endpoint", "network", "memory"]:
        ar = AgentResult("id", "host", mode, result, "T1071.004", 1.0)
        assert ar.mode == mode
