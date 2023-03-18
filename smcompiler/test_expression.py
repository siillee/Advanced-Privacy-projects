"""
Unit tests for expressions.
Testing expressions is not obligatory.

MODIFY THIS FILE.
"""

from expression import Secret, Scalar


# Example test, you can adapt it to your needs.
def test_expr_construction():
    a = Secret(1)
    b = Secret(2)
    c = Secret(3)
    expr = (a + b) * c * Scalar(4) + Scalar(3)
    assert repr(expr) == "((Secret(1) + Secret(2)) * Secret(3) * Scalar(4) + Scalar(3))"

# Very similar test to the one above, just with some more elements plus added some subtraction operations. 
def test_expr_construction2():
    a = Secret(1)
    b = Secret(2)
    c = Secret(3)
    expr = (a + b) * c - Scalar(4) - Scalar(3) + Scalar(2) * Scalar(5)
    assert repr(expr) == "((((Secret(1) + Secret(2)) * Secret(3) - Scalar(4)) - Scalar(3)) + Scalar(2) * Scalar(5))"

# def test():
#     raise NotImplementedError("You can create some tests.")
