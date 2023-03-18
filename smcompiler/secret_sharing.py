"""
Secret sharing scheme.
"""

from __future__ import annotations

from typing import List

# Added imports
import random
import pickle
from expression import Secret

class Share:
    """
    A secret share in a finite field.
    """

    prime = 999983 # some temporary value, representing prime p in the field Fp (some set F)

    # Adapt constructor arguments as you wish
    def __init__(self, share_value: int, id: bytes):

        self.share_value = share_value
        self.id = id


    def __repr__(self):
        # Helps with debugging.
        return f"{self.__class__.__name__}({repr(self.share_value)}, {repr(self.id)})"

    def __add__(self, other):
        
        if isinstance(other, Share):
            self.share_value = (self.share_value + other.share_value) % self.prime
            return self
        
        self.share_value = (self.share_value + other) % self.prime
        return self

    def __sub__(self, other):

        if isinstance(other, Share):
            self.share_value = (self.share_value - other.share_value) % self.prime
            return self

        self.share_value = (self.share_value - other) % self.prime
        return self

    def __mul__(self, other):

        # TODO: They mentioned scalar multiplication is based on addition, but idk if it has to be done this way, 
        #       rather than just multiplying the value (not using addition k-1 times, where k is the scalar). 
        if isinstance(other, int):
            org_value = self.share_value
            for _ in range(other-1):
                    self.share_value += org_value
            # self.share_value = (self.share_value * other) % self.prime
        
        return self

    def serialize(self):
        """Generate a representation suitable for passing in a message."""
        return pickle.dumps(self)

    @staticmethod
    def deserialize(serialized) -> Share:
        """Restore object from its serialized representation."""
        return pickle.loads(serialized)

# I changed the original def by adding the secObj: Secret parameter, I guess it is not a problem. 
def share_secret(secret: int, num_shares: int, secObj: Secret) -> List[Share]:
    """Generate secret shares."""

    secret_shares = []
    sum = 0
    for i in range(0, num_shares-1):
        random_share_value = random.randint(0, Share.prime - 1)
        sum += random_share_value
        secret_shares.append(Share(random_share_value, secObj.id))

    secret_shares.insert(0, Share(secret - sum, secObj.id))

    return secret_shares


def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""
    
    secret = 0
    for share in shares:
        secret = secret + share.share_value

    return secret % Share.prime 

# Feel free to add as many methods as you want.
