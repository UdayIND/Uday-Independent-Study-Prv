"""
SENTINEL-RL Heterogeneous Graph Attention Network (HetGAT) Encoder.

Section IV-B: A HetGAT encoder pulls a two-hop neighborhood surrounding
suspicious activity and compresses this localized topological map into a
64-dimensional dense vector, s_t ∈ R^64.

Graph schema (Section IV-A):
  Node types: Host, User, Service, NetworkSegment
  Edge types: (Host)-[:AUTH]->(Host), (User)-[:AUTHENTICATES_TO]->(Host)
"""

import torch
import torch.nn as nn

try:
    from torch_geometric.nn import HANConv

    HAS_TORCH_GEOMETRIC = True
except ImportError:
    HAS_TORCH_GEOMETRIC = False


class HetGATEncoder(nn.Module):
    """Heterogeneous Graph Attention Network encoder.

    Compresses a 2-hop authentication subgraph from Neo4j into a dense
    64-dimensional state vector for the PPO policy.

    Architecture (from paper):
      Layer 1: HANConv(in_channels → hidden_channels), heads=4
      Layer 2: HANConv(hidden_channels → out_channels), heads=1
      Linear:  out_channels → 64
    """

    # Graph metadata matching the paper's schema (Section IV-A)
    METADATA = (
        ["host", "user"],
        [
            ("host", "auth", "host"),  # Host-to-Host authentication
            ("user", "authenticates_to", "host"),  # User-to-Host credential use
        ],
    )

    def __init__(
        self,
        in_channels: int = 16,
        hidden_channels: int = 64,
        out_channels: int = 64,
    ):
        super().__init__()

        if not HAS_TORCH_GEOMETRIC:
            raise ImportError(
                "torch_geometric is required for HetGATEncoder. "
                "Install with: pip install torch_geometric"
            )

        self.han1 = HANConv(in_channels, hidden_channels, self.METADATA, heads=4)
        self.han2 = HANConv(hidden_channels, out_channels, self.METADATA, heads=1)
        self.projection = nn.Linear(out_channels, 64)

    def forward(self, x_dict: dict, edge_index_dict: dict) -> torch.Tensor:
        """Encode a heterogeneous subgraph into a 64-d state vector.

        Args:
            x_dict: Node feature tensors keyed by type.
                    e.g., {'host': Tensor[N, 16], 'user': Tensor[M, 16]}
            edge_index_dict: Edge index tensors keyed by relation tuple.

        Returns:
            64-dimensional state vector (s_t) for the PPO policy.
        """
        # Layer 1: multi-head attention
        out_raw = self.han1(x_dict, edge_index_dict)
        out = {}
        for key, val in out_raw.items():
            if val is not None:
                out[key] = torch.relu(val)
            else:
                num_nodes = x_dict[key].size(0)
                # In PyG HANConv, heads might be averaged or concatenated.
                # We can just look at another valid output tensor's shape.
                # But since we need a deterministic shape: han1 returns hidden_channels.
                out_dim = self.han1.out_channels
                out[key] = torch.zeros((num_nodes, out_dim), device=x_dict[key].device)

        # Layer 2: single-head attention
        out = self.han2(out, edge_index_dict)

        # Global mean pooling over host nodes → graph-level embedding
        host_embedding = out["host"].mean(dim=0)

        # Project to 64-d state vector
        state_vector = self.projection(host_embedding)
        return state_vector

    @staticmethod
    def extract_subgraph_from_neo4j(driver, alert_host_id: str, hops: int = 2) -> dict:
        """Extract a k-hop authentication subgraph from Neo4j.

        This is the bridge between the Data Plane and the Strategic Plane.
        Returns raw data that should be converted to PyG HeteroData.

        Args:
            driver: Neo4j driver instance.
            alert_host_id: The alerted host ID to center the subgraph on.
            hops: Number of hops to expand (paper uses 2).

        Returns:
            Dictionary with 'nodes' and 'edges' for conversion to HeteroData.
        """
        query = f"""
        MATCH path = (center:Host {{id: $host_id}})-[:AUTH*1..{hops}]-(neighbor)
        RETURN path
        LIMIT 500
        """
        nodes = {}
        edges = []

        with driver.session() as session:
            result = session.run(query, host_id=alert_host_id)
            for record in result:
                path = record["path"]
                for node in path.nodes:
                    node_id = node.element_id
                    if node_id not in nodes:
                        nodes[node_id] = dict(node)
                for rel in path.relationships:
                    edges.append(
                        {
                            "src": rel.start_node.element_id,
                            "dst": rel.end_node.element_id,
                            "type": rel.type,
                            "properties": dict(rel),
                        }
                    )

        return {"nodes": nodes, "edges": edges}
