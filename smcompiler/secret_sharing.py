"""
Secret sharing scheme.
"""

from __future__ import annotations

from typing import List

# Added imports
import random
import jsonpickle
from expression import Secret

class Share:
    """
    A secret share in a finite field.
    """
                
    prime = 340282366920938463463374607431768211507  # some temporary value, representing prime p in the field (it's a 128 bit prime)

    # Adapt constructor arguments as you wish
    def __init__(self, share_value: int):

        self.share_value = share_value

    def __repr__(self):
        # Helps with debugging.
        return f"{self.__class__.__name__}({repr(self.share_value)})"

    def __add__(self, other):
        
        if isinstance(other, Share):
            return Share((self.share_value + other.share_value) % self.prime)
        
        return Share((self.share_value + other) % self.prime)

    def __sub__(self, other):

        if isinstance(other, Share):
            return Share((self.share_value - other.share_value) % self.prime)

        return Share((self.share_value - other) % self.prime)

    def __mul__(self, other):

        if isinstance(other, int):
            return Share((self.share_value * other) % self.prime)
        return self

    def serialize(self):
        """Generate a representation suitable for passing in a message."""
        return jsonpickle.encode(self)

    @staticmethod
    def deserialize(serialized) -> Share:
        """Restore object from its serialized representation."""
        return jsonpickle.decode(serialized)

# I changed the original def by adding the secObj: Secret parameter, I guess it is not a problem. 
def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate secret shares."""

    secret_shares = []
    sum = 0
    for i in range(0, num_shares-1):
        random_share_value = random.randint(0, Share.prime - 1)
        sum += random_share_value
        secret_shares.append(Share(random_share_value))

    secret_shares.insert(0, Share((secret - sum) % Share.prime))

    return secret_shares


def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""
    
    secret = 0
    for share in shares:
        secret = secret + share.share_value

    return secret % Share.prime 

# Feel free to add as many methods as you want.
