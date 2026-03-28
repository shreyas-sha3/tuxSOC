from langgraph.graph import StateGraph, END
from agent.agent_state import AgentState
from agent.agent_nodes import analyze_incident_master, patch_and_fix, finalize_and_validate

def build_graph():
    graph = StateGraph(AgentState)

    # Register the 3 nodes
    graph.add_node("analyze", analyze_incident_master)
    graph.add_node("patch", patch_and_fix)
    graph.add_node("validate", finalize_and_validate)

    # Set the flow: Start -> Analyze -> Patch -> Validate -> End
    graph.set_entry_point("analyze")
    graph.add_edge("analyze", "patch")
    graph.add_edge("patch", "validate")
    graph.add_edge("validate", END)

    return graph.compile()