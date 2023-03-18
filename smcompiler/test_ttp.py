"""
Unit tests for the trusted parameter generator.
Testing ttp is not obligatory.

MODIFY THIS FILE.
"""

from ttp import TrustedParamGenerator


# def test():
#     raise NotImplementedError("You can create some tests.")


def test_beaver_triplet_gen():

    ttp = TrustedParamGenerator()
    ttp.add_participant("Alice")
    ttp.add_participant("Bob")

    alice_share = ttp.retrieve_share("Alice", "MultOp1")
    assert len(alice_share) == 3
    bob_share = ttp.retrieve_share("Bob", "MultOp1")
    assert len(bob_share) == 3
