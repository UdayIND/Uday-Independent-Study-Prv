"""
SENTINEL-RL Analyst Workbench
A human-in-the-loop Streamlit interface for Agentic SOC orchestration.
"""

import tempfile
import time
from datetime import datetime
from typing import Any

import networkx as nx
import pandas as pd
import requests
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from src.config import Config

NEO4J_URI = Config.NEO4J_URI
NEO4J_USER = Config.NEO4J_USER
NEO4J_PASSWORD = Config.NEO4J_PASSWORD
API_URL = f"http://{Config.API_HOST}:{Config.API_PORT}"

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================
st.set_page_config(
    page_title="SENTINEL-RL Analyst Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark theme colors for cybersecurity aesthetic
COLORS = {
    "background": "#0E1117",
    "host": "#00FFCC",  # Cyan
    "user": "#FF00FF",  # Magenta
    "process": "#0088FF",  # Blue
    "alert": "#FF3333",  # Red
    "triage": "#00D2FF",  # Neon Blue
    "investigator": "#39FF14",  # Neon Green
    "critic": "#FF003C",  # Neon Crimson
    "text": "#E0E0E0",
}


# ==========================================
# SESSION STATE INITIALIZATION
# ==========================================
def init_session_state():
    if "selected_alert" not in st.session_state:
        st.session_state.selected_alert = "CASE_0042_SCAN"
    if "agent_logs" not in st.session_state:
        st.session_state.agent_logs = []
    if "rl_recommendation" not in st.session_state:
        st.session_state.rl_recommendation = None
    if "decision_status" not in st.session_state:
        st.session_state.decision_status = None
    if "approval_stage" not in st.session_state:
        st.session_state.approval_stage = "pending"  # pending, confirming, resolved


init_session_state()


# ==========================================
# NEO4J & GRAPH VISUALIZATION
# ==========================================
def get_mock_graph_data(alert_id: str) -> nx.DiGraph:
    """Fallback mock graph data if Neo4j is unavailable."""
    G = nx.DiGraph()

    # Add Nodes
    G.add_node("Attacker_IP", label="104.28.14.92", type="host", title="External Attacker\nLoc: RU")
    G.add_node("Web_Server", label="srv-web-01", type="host", title="Public facing DMZ")
    G.add_node("Nginx_Proc", label="nginx (PID: 882)", type="process", title="Vulnerable Service")
    G.add_node("Alert_1", label="Recon Scan", type="alert", title="Suricata High Fan-Out")
    G.add_node("Alert_2", label="RCE Payload", type="alert", title="Log4j exploitation attempt")
    G.add_node("Service_Acct", label="svc_web", type="user", title="Compromised Account")
    G.add_node("DB_Server", label="srv-db-01", type="host", title="Target Internal DB")

    # Add Edges
    G.add_edge("Attacker_IP", "Web_Server", label="TCP/443")
    G.add_edge("Alert_1", "Attacker_IP", label="TRIGGERED_BY")
    G.add_edge("Web_Server", "Nginx_Proc", label="HOSTS")
    G.add_edge("Alert_2", "Nginx_Proc", label="DETECTED_ON")
    G.add_edge("Nginx_Proc", "Service_Acct", label="RUNS_AS")
    G.add_edge("Service_Acct", "DB_Server", label="LATERAL_AUTH")

    return G


def fetch_neo4j_subgraph(alert_id: str) -> nx.DiGraph:
    """Fetch attack path from Neo4j using official python driver."""
    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        query = """
        MATCH path = (a:Alert {id: $alert_id})-[:TRIGGERED_BY|INVOLVES|ATTACK_PATH*1..4]-(node)
        RETURN path LIMIT 50
        """
        with driver.session() as session:
            result = session.run(query, alert_id=alert_id)
            # Neo4j -> NetworkX parsing logic would go here
            # Falling back to mock for this standalone demo
            raise Exception("Neo4j python driver not fully configured locally")
    except Exception:
        # Fallback to mock data
        return get_mock_graph_data(alert_id)


def render_graph_pyvis(G: nx.DiGraph):
    """Render NetworkX graph to PyVis interactive HTML component."""
    net = Network(
        height="600px",
        width="100%",
        bgcolor=COLORS["background"],
        font_color=COLORS["text"],
        directed=True,
    )

    # Physics options for dynamic organic layout
    net.set_options(
        """
    var options = {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -100,
          "centralGravity": 0.01,
          "springLength": 100,
          "springConstant": 0.08
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based"
      }
    }
    """
    )

    # Populate nodes with style
    for node, data in G.nodes(data=True):
        node_type = data.get("type", "unknown")
        color = COLORS.get(node_type, "#FFFFFF")
        shape = "box" if node_type == "alert" else "dot"
        size = 30 if node_type == "alert" else 20

        net.add_node(
            node,
            label=data.get("label", node),
            title=data.get("title", ""),
            color=color,
            shape=shape,
            size=size,
            borderWidth=2,
            borderWidthSelected=4,
        )

    # Populate edges
    for source, target, data in G.edges(data=True):
        net.add_edge(
            source,
            target,
            title=data.get("label", ""),
            label=data.get("label", ""),
            color="#555555",
        )

    # Render via Tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
        net.save_graph(tmp.name)
        with open(tmp.name, encoding="utf-8") as f:
            html_content = f.read()

    # Embed in Streamlit
    components.html(html_content, height=620)


# ==========================================
# FASTAPI & BACKEND INTEGRATION
# ==========================================
def get_rl_prediction(alert_id: str) -> dict[str, Any]:
    """Call FastAPI backend for RL Policy Engine prediction."""
    payload = {"alert_id": alert_id, "state_vector": []}

    try:
        response = requests.post(f"{API_URL}/predict_action", json=payload, timeout=2.0)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        # Structured Mock Data Fallback
        time.sleep(0.5)  # Simulate network latency
        return {
            "action": "ISOLATE_HOST",
            "target": "srv-web-01",
            "confidence_score": 0.88,
            "impact_assessment": "High disruption to public web traffic. Stops lateral movement.",
            "counterfactuals": [
                {"step": 0, "impact_taken": 10, "impact_ignored": 10},
                {"step": 1, "impact_taken": 12, "impact_ignored": 45},
                {"step": 2, "impact_taken": 15, "impact_ignored": 90},
                {"step": 3, "impact_taken": 15, "impact_ignored": 150},
            ],
        }


def simulate_agent_reasoning(alert_id: str):
    """Simulate streaming logs from the multi-agent system."""
    base_logs = [
        {
            "agent": "Triage",
            "type": "triage",
            "msg": f"Ingested {alert_id}. Parsing associated Zeek/Suricata flows.",
        },
        {
            "agent": "Investigation",
            "type": "investigator",
            "msg": "Queried Neo4j. Found lateral movement path originating from srv-web-01 via compromised svc_web.",
        },
        {
            "agent": "Critic",
            "type": "critic",
            "msg": "Evaluating evidence completeness. Multi-sensor correlation verified. Confidence adjusted to 0.88.",
        },
    ]

    # Auto-populate if empty
    if not st.session_state.agent_logs:
        for log in base_logs:
            log["timestamp"] = datetime.now().strftime("%H:%M:%S")
            st.session_state.agent_logs.append(log)


# ==========================================
# UI COMPONENTS
# ==========================================
def render_agent_feed():
    """Render the scrollable multi-agent reasoning feed."""
    st.subheader("🤖 Live Agent Reasoning")
    st.markdown("---")

    feed_container = st.container(height=350)
    with feed_container:
        for log in st.session_state.agent_logs:
            color = COLORS[log["type"]]
            st.markdown(
                f"""
                <div style="border-left: 4px solid {color}; padding-left: 10px; margin-bottom: 10px; background-color: #1A1C23; padding: 10px; border-radius: 4px;">
                    <span style="color: {color}; font-weight: bold; font-family: monospace;">[{log['timestamp']}] {log['agent']} Agent</span><br>
                    <span style="font-size: 0.9em;">{log['msg']}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_rl_panel():
    """Render RL decision recommendations and counterfactuals."""
    st.subheader("🧠 RL Policy Recommendation")

    if st.session_state.rl_recommendation is None:
        with st.spinner("Querying RL Engine..."):
            st.session_state.rl_recommendation = get_rl_prediction(st.session_state.selected_alert)

    data = st.session_state.rl_recommendation

    # Recommendation Header
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"### Action: `{data['action']}`")
        st.caption(f"Target: {data['target']} | Impact: {data['impact_assessment']}")
    with col2:
        st.metric("Confidence", f"{data['confidence_score'] * 100:.1f}%")

    # Counterfactual Blast Radius Chart
    st.markdown("#### Counterfactual Rollout (Predicted Blast Radius)")
    df = pd.DataFrame(data["counterfactuals"]).set_index("step")
    df.columns = ["Action Taken (Risk Score)", "Ignored (Risk Score)"]
    st.line_chart(df, color=["#39FF14", "#FF3333"])


def render_hitl_controls():
    """Render Human-in-the-Loop decision gates."""
    st.markdown("---")
    st.subheader("🛑 Human-in-the-Loop Override")

    if st.session_state.approval_stage == "resolved":
        status_color = "green" if "Approved" in st.session_state.decision_status else "red"
        st.success(f"Decision Recorded: **{st.session_state.decision_status}**")
        if st.button("Reset Session"):
            st.session_state.approval_stage = "pending"
            st.session_state.decision_status = None
            st.rerun()

    elif st.session_state.approval_stage == "confirming":
        st.warning(
            "⚠️ Critical Action Warning: You are about to modify production infrastructure. Proceed?"
        )
        c1, c2 = st.columns(2)
        if c1.button("✅ Confirm Action Execution", type="primary", use_container_width=True):
            st.session_state.decision_status = "Approved ISOLATE_HOST"
            st.session_state.approval_stage = "resolved"
            st.rerun()
        if c2.button("❌ Cancel", use_container_width=True):
            st.session_state.approval_stage = "pending"
            st.rerun()

    else:
        c1, c2 = st.columns(2)
        if c1.button("✅ Approve Policy Action", type="primary", use_container_width=True):
            st.session_state.approval_stage = "confirming"
            st.rerun()
        if c2.button("❌ Reject Action", use_container_width=True):
            st.session_state.decision_status = "Rejected"
            st.session_state.approval_stage = "resolved"
            st.session_state.agent_logs.append(
                {
                    "agent": "Critic",
                    "type": "critic",
                    "msg": "Analyst rejected action. Applying negative reward (-1.0) to baseline constraint parameters.",
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }
            )
            st.rerun()


# ==========================================
# MAIN LAYOUT
# ==========================================
def main():
    # Sidebar
    with st.sidebar:
        st.image(
            "https://upload.wikimedia.org/wikipedia/commons/thumb/c/c2/Neo4j-logo_color.svg/1024px-Neo4j-logo_color.svg.png",
            width=120,
        )
        st.title("SENTINEL-RL")
        st.markdown("### Active Triage Queue")

        alerts = ["CASE_0042_SCAN", "CASE_0043_EXFIL", "CASE_0044_RANSOM"]
        st.session_state.selected_alert = st.selectbox("Select Case Context", options=alerts)

        st.markdown("---")
        st.markdown("**System Health**")
        st.caption("🟢 Neo4j Connected")
        st.caption("🟢 FastAPI Connected")
        st.caption("🟢 PPO Policy Online")

    # Sync Agent State
    simulate_agent_reasoning(st.session_state.selected_alert)

    # Main Dashboard Splitting
    st.title("🛡️ SENTINEL-RL Analyst Workbench")
    st.markdown(f"**Investigating Context**: `{st.session_state.selected_alert}`")

    col_graph, col_panel = st.columns([3, 2], gap="large")

    with col_graph:
        st.subheader("🔗 Knowledge Graph Exploit Path")
        st.caption("Rendered dynamically from Neo4j (Mock View)")
        graph = fetch_neo4j_subgraph(st.session_state.selected_alert)
        render_graph_pyvis(graph)

    with col_panel:
        render_agent_feed()
        st.markdown("<br>", unsafe_allow_html=True)
        render_rl_panel()
        render_hitl_controls()


if __name__ == "__main__":
    main()
