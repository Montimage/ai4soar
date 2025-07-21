import json
import networkx as nx
from typing import Dict, List, Tuple, Optional
from openai import OpenAI
import os
from dataclasses import dataclass
from enum import Enum

class VerificationScore(Enum):
    NO_ERROR = 100
    MINOR_ISSUE = 80
    MODERATE_ISSUE = 60
    MAJOR_ISSUE = 40
    CRITICAL_ISSUE = 20

@dataclass
class VerificationIssue:
    description: str
    score: int
    node_id: Optional[str] = None
    severity: str = "warning"

@dataclass
class NodeInfo:
    id: str
    name: str
    description: str
    api: Optional[str] = None
    next_nodes: List[str] = None

class PlaybookVerifier:
    def __init__(self, use_local_model: bool = False):
        self.use_local_model = use_local_model
        if not use_local_model:
            # Initialize OpenAI client
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY environment variable not set")
            self.client = OpenAI(api_key=api_key)

    def parse_playbook(self, playbook_data: Dict) -> Tuple[nx.DiGraph, Dict[str, NodeInfo]]:
        """
        Parse playbook data into a directed graph and node information dictionary
        """
        G = nx.DiGraph()
        nodes_info = {}

        # Parse nodes
        for node in playbook_data.get("nodes", []):
            node_id = node.get("id")
            node_info = NodeInfo(
                id=node_id,
                name=node.get("name", ""),
                description=node.get("description", ""),
                api=node.get("api"),
                next_nodes=node.get("next", [])
            )
            nodes_info[node_id] = node_info
            G.add_node(node_id)

        # Add edges
        for node_id, node_info in nodes_info.items():
            if node_info.next_nodes:
                for next_node in node_info.next_nodes:
                    G.add_edge(node_id, next_node)

        return G, nodes_info

    def verify_playbook_structure(self, G: nx.DiGraph) -> List[VerificationIssue]:
        """
        Verify basic playbook structure using graph analysis
        """
        issues = []

        # Check for cycles
        if not nx.is_directed_acyclic_graph(G):
            issues.append(VerificationIssue(
                description="Playbook contains cycles which may lead to infinite loops",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error"
            ))

        # Check for unreachable nodes
        start_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        if not start_nodes:
            issues.append(VerificationIssue(
                description="No start node found in playbook",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error"
            ))

        # Check for nodes with no outgoing edges (except end nodes)
        end_nodes = [n for n in G.nodes() if G.out_degree(n) == 0]
        if not end_nodes:
            issues.append(VerificationIssue(
                description="No end node found in playbook",
                score=VerificationScore.CRITICAL_ISSUE.value,
                severity="error"
            ))

        return issues

    def verify_with_llm(self, nodes_info: Dict[str, NodeInfo]) -> List[VerificationIssue]:
        """
        Verify playbook logic using LLM
        """
        # Prepare context for LLM
        context = (
            "You are a playbook verification expert focused on identifying logical contradictions. Analyze the following playbook nodes, considering all provided details for each node (Name, Description, API, Code, Parameters, Next nodes), to detect any sequences of actions that are impossible or illogical due to a previous action (e.g., analyzing a file after it has been deleted). "
            "Focus ONLY on logical contradictions in the workflow. Do NOT report minor issues, best practices, or general suggestions. "
            "If you find a contradiction, clearly identify the nodes involved and explain the logical inconsistency. If no logical contradiction is detected based on the provided information, state: 'No logical contradiction detected.'\n\n"
        )
        for node_id, node in nodes_info.items():
            context += f"Node {node_id}:\n"
            context += f"Name: {node.name}\n"
            context += f"Description: {node.description}\n"
            if hasattr(node, 'code') and node.code:
                context += f"Code: {node.code}\n"
            elif hasattr(node, 'parameters') and isinstance(node.parameters, dict):
                for param_name, param_value in node.parameters.items():
                    context += f"Parameter {param_name}: {param_value}\n"
            if node.api:
                context += f"API: {node.api}\n"
            if node.next_nodes:
                context += f"Next nodes: {', '.join(node.next_nodes)}\n"
            context += "\n"

        if self.use_local_model:
            # Use Ollama for local model
            import requests
            response = requests.post('http://localhost:11434/api/generate',
                                  json={
                                      "model": "llama2",
                                      "prompt": context,
                                      "stream": False
                                  })
            analysis = response.json()['response']
        else:
            # Use OpenAI GPT-4 with new API
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "user", "content": context}
                ]
            )
            analysis = response.choices[0].message.content

        # Parse LLM response and convert to verification issues
        issues = []
        # Look for specific terms indicating a detected contradiction
        contradiction_terms = ["contradiction", "inconsistency", "illogical", "impossible", "should be reversed"]
        normalized_analysis = analysis.strip().lower()
        if "no logical contradiction detected" not in normalized_analysis:
            # Only treat as issue if it actually points out a contradiction
            issues.append(VerificationIssue(
                description=analysis,
                score=VerificationScore.MODERATE_ISSUE.value,
                severity="warning"
            ))

        return issues

    def verify_playbook(self, playbook_data: Dict) -> Dict:
        """
        Main verification method that combines structural and LLM verification
        """
        # Parse playbook
        G, nodes_info = self.parse_playbook(playbook_data)

        # Get structural verification issues
        structural_issues = self.verify_playbook_structure(G)

        # Get LLM verification issues
        llm_issues = self.verify_with_llm(nodes_info)

        # Combine all issues
        all_issues = structural_issues + llm_issues

        # Calculate overall score
        if not all_issues:
            overall_score = VerificationScore.NO_ERROR.value
        else:
            overall_score = min(issue.score for issue in all_issues)

        return {
            "overall_score": overall_score,
            "issues": [
                {
                    "description": issue.description,
                    "score": issue.score,
                    "node_id": issue.node_id,
                    "severity": issue.severity
                }
                for issue in all_issues
            ]
        }

def simplify_shuffle_playbook(shuffle_json):
    # Build node map
    nodes = {}
    for action in shuffle_json.get("actions", []):
        node_id = action["id"]
        # Get the main code/command if available
        code_param = next((p["value"] for p in action.get("parameters", []) if p["name"] == "code"), None)
        nodes[node_id] = {
            "id": node_id,
            "name": action.get("label") or action.get("name"),
            "description": action.get("description", ""),
            "api": action.get("app_name", ""),
            "parameters": {p["name"]: p.get("value", "") for p in action.get("parameters", [])},
            "code": code_param,
            "next": []
        }

    # Build connections (branches)
    for branch in shuffle_json.get("branches", []):
        src = branch["source_id"]
        dst = branch["destination_id"]
        if src in nodes:
            nodes[src]["next"].append(dst)

    # Remove parameters if you want a minimal version
    for node in nodes.values():
        if not node["parameters"]:
            del node["parameters"]
        if not node["code"]:
            del node["code"]

    return {"nodes": list(nodes.values())}