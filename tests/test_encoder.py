"""Tests for the SENTINEL-RL Strategic Plane — HetGAT Encoder."""

import torch
from torch_geometric.data import HeteroData

from src.model.encoder import HetGATEncoder


class TestHetGATEncoder:
    """Test the HetGAT graph encoder (Section IV-B)."""

    def test_encoder_initialization(self):
        """Test the encoder initializes without error."""
        encoder = HetGATEncoder(in_channels=16, hidden_channels=64, out_channels=64)
        assert encoder.han1 is not None
        assert encoder.han2 is not None
        assert encoder.projection is not None

    def test_encoder_forward_pass(self):
        """Test a forward pass on a dummy heterogeneous graph."""
        encoder = HetGATEncoder(in_channels=16, hidden_channels=32, out_channels=32)

        data = HeteroData()

        # Add node features (simulating 2 users and 3 hosts)
        data["user"].x = torch.randn(2, 16)
        data["host"].x = torch.randn(3, 16)

        # Ensure edge types exactly match METADATA in HetGATEncoder
        # ("host", "auth", "host")
        edge_index_host_auth = torch.tensor([[0, 1], [1, 2]], dtype=torch.long)
        data["host", "auth", "host"].edge_index = edge_index_host_auth

        # ("user", "authenticates_to", "host")
        edge_index_user_auth = torch.tensor([[0, 1], [0, 2]], dtype=torch.long)
        data["user", "authenticates_to", "host"].edge_index = edge_index_user_auth

        x_dict = data.x_dict
        edge_index_dict = data.edge_index_dict

        # Forward pass
        state_vector = encoder(x_dict, edge_index_dict)

        # Validate output shape
        assert state_vector.shape == (64,)
