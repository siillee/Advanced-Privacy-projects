"""
Trusted parameters generator.

MODIFY THIS FILE.
"""

import collections
from typing import (
    Dict,
    Set,
    Tuple,
)

from communication import Communication
from secret_sharing import(
    share_secret,
    Share,
)

# Feel free to add as many imports as you want.

import random
from expression import Secret


class TrustedParamGenerator:
    """
    A trusted third party that generates random values for the Beaver triplet multiplication scheme.
    """

    def __init__(self):
        self.participant_ids: Set[str] = set()
        self.triplet_map: Dict[str, Dict[str, Tuple[Share, Share, Share]]] = {}

    def add_participant(self, participant_id: str) -> None:
        """
        Add a participant.
        """
        self.participant_ids.add(participant_id)

    def retrieve_share(self, client_id: str, op_id: str) -> Tuple[Share, Share, Share]:
        """
        Retrieve a triplet of shares for a given client_id.
        """
        
        if op_id not in self.triplet_map:
            self.generate_triplet(op_id)
        
        return self.triplet_map[op_id][client_id]


    # Feel free to add as many methods as you want.

    def generate_triplet(self, op_id: str):

        # Generating the secrets a, b, and c for the Beaver triplet.
        p = Share.prime
        a = random.randint(0, p - 1)
        b = random.randint(0, p - 1)
        c = (a * b) % p

        # Creating the shares of the secrets 
        a_shares = share_secret(a, len(self.participant_ids))
        b_shares = share_secret(b, len(self.participant_ids))
        c_shares = share_secret(c, len(self.participant_ids))

        # Populate the map with the shares of the triplet. Each client_id represents the share for that client. 
        self.triplet_map[op_id] = {}
        for i, client_id in enumerate(self.participant_ids):
            self.triplet_map[op_id][client_id] = (a_shares[i], b_shares[i], c_shares[i])
    