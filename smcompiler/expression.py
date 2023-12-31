"""
Tools for building arithmetic expressions to execute with SMC.

Example expression:
>>> alice_secret = Secret()
>>> bob_secret = Secret()
>>> expr = alice_secret * bob_secret * Scalar(2)

MODIFY THIS FILE.
"""

import base64
import random
from typing import Optional


ID_BYTES = 4


def gen_id() -> bytes:
    id_bytes = bytearray(
        random.getrandbits(8) for _ in range(ID_BYTES)
    )
    return base64.b64encode(id_bytes)


class Expression:
    """
    Base class for an arithmetic expression.
    """

    def __init__(
            self,
            id: Optional[bytes] = None
        ):
        # If ID is not given, then generate one.
        if id is None:
            id = gen_id()
        self.id = id

    def __add__(self, other):
        return AddOp(self, other)


    def __sub__(self, other):
        return SubOp(self, other)


    def __mul__(self, other):
        return MultOp(self, other)


    def __hash__(self):
        return hash(self.id)


class AddOp(Expression):

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def __repr__(self):
        return f"({repr(self.a)} + {repr(self.b)})"

    def __hash__(self):
        return

class SubOp(Expression):

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def __repr__(self):
        return f"({repr(self.a)} - {repr(self.b)})"

    def __hash__(self):
        return

class MultOp(Expression):

    def __init__(self, a, b, id:Optional[bytes] = None):
        self.a = a
        self.b = b
        super().__init__(id)

    def __repr__(self):
        return f"{repr(self.a)} * {repr(self.b)}"

    def __hash__(self):
        return

class Scalar(Expression):
    """Term representing a scalar finite field value."""

    def __init__(
            self,
            value: int,
            id: Optional[bytes] = None
        ):
        self.value = value
        super().__init__(id)


    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.value)})"


    def __hash__(self):
        return



class Secret(Expression):
    """Term representing a secret finite field value (variable)."""

    def __init__(
            self,
            value: Optional[int] = None,
            id: Optional[bytes] = None
        ):
        self.value = value
        super().__init__(id)


    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.value if self.value is not None else ''})"
        )


