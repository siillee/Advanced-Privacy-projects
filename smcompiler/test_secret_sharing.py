"""
Unit tests for the secret sharing scheme.
Testing secret sharing is not obligatory.

MODIFY THIS FILE.
"""

from expression import Secret, Scalar
from secret_sharing import Share, share_secret, reconstruct_secret

def test_addition():

    a = Secret(5)
    b = Secret(7)

    a_shares = share_secret(a.value, 2)
    b_shares = share_secret(b.value, 2)

    assert len(a_shares) == 2
    assert len(b_shares) == 2

    res_shares = []
    for i in range (0, len(a_shares)):
        res_shares.append(a_shares[i] + b_shares[i])

    res = reconstruct_secret(res_shares)
    assert res == 12

def test_subtraction():

    a = Secret(18)
    b = Secret(7)

    a_shares = share_secret(a.value, 2)
    b_shares = share_secret(b.value, 2)

    assert len(a_shares) == 2
    assert len(b_shares) == 2

    res_shares = []
    for i in range (0, len(a_shares)):
        res_shares.append(a_shares[i] - b_shares[i])

    res = reconstruct_secret(res_shares)
    assert res == 11

def test_scalar_multiplication():

    a = Secret(7)
    k = Scalar(3)

    a_shares = share_secret(a.value, 2)
    assert len(a_shares) == 2

    res_shares = []
    for i in range (0, len(a_shares)):
        res_shares.append(a_shares[i] * k)

    res = reconstruct_secret(res_shares)
    assert res == 21
