"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import  List, Tuple

from serialization import jsonpickle

from hashlib import sha256

# Import petrelic primitives

# Bn is the class for big integers modulo the group order, secure and fast
from petrelic.bn import Bn
# G1 and G2 are the classes for elliptic curve points in the respective groups
# GT, the target group, is used for its bilinear pairing function
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
# SecretKey = Any
Attribute = Bn
AttributeMap = dict[int, Attribute]


class SecretKey:

    def __init__(self, x: Bn, X: Bn, y: List[Bn]) -> None:
        self.x = x
        self.X = X
        self.y = y


# PublicKey = Any
class PublicKey:

    def __init__(
        self,
        g: G1Element,
        Y: List[Bn],
        g_hat: G2Element,
        X_hat: G2Element,
        Y_hat: List[Bn],
        attributes: List[Attribute],
    ) -> None:
        self.g = g
        self.Y = Y
        self.g_hat = g_hat
        self.X_hat = X_hat
        self.Y_hat = Y_hat
        self.pk = [g] + Y + [g_hat, X_hat] + Y_hat
        self.attr = attributes


# Signature = Any

class Signature:

    def __init__(self, s1: G1Element, s2: G1Element) -> None:
        self.sigma = (s1, s2)


# IssueRequest = Any

class NonInteractiveProof:

    def __init__(
        self,
        challenge: Bn,
        response_0: Bn,
        response_attr_index: List[Tuple[Attribute, int]],
    ) -> None:
        self.challenge = challenge.mod(G1.order())
        self.response_0 = response_0.mod(G1.order())
        self.response_index = [
            (attr.mod(G1.order()), index) for attr, index in response_attr_index
        ]


class IssueRequest:

    def __init__(self, c: G1Element, pi: NonInteractiveProof) -> None:
        self.c = c
        self.pi = pi


# BlindSignature = Any
class BlindSignature:

    def __init__(
        self, g_u: G1Element, prod_u: G1Element, issuerAttributes: AttributeMap
    ) -> None:
        self.sigma = (g_u, prod_u)
        self.issuerAttributes = issuerAttributes

# AnonymousCredential = Any


class AnonymousCredential:

    def __init__(self, signature: Signature, attributes: AttributeMap) -> None:
        self.signature = signature
        self.attributes = dict(
            map(lambda x: (x[0], x[1].mod(G1.order())), attributes.items())
        )


# DisclosureProof = Any

class DisclosureProof:

    def __init__(self, signature: Signature, proof: NonInteractiveProof) -> None:
        self.signature = signature
        self.pi = proof


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
    attributes: List[Attribute]
) -> Tuple[SecretKey, PublicKey]:

    L = len(attributes)
    if L < 1:
        raise ValueError("Key generation requires at least one attribute")
    for attr in attributes:
        if not isinstance(attr, Bn) or not attr >= 0:
            raise TypeError("Attributes should be positive integers")

    y = [G1.order().random() for _ in range(L)]

    # Private key
    g = G1.generator()
    x = G1.order().random()
    X = g**x
    sk = SecretKey(x, X, y)

    # Public key
    g_hat = G2.generator()
    X_hat = g_hat**x
    Y = [g**y_i for y_i in y]
    Y_hat = [g_hat**y_i for y_i in y]
    pk = PublicKey(g, Y, g_hat, X_hat, Y_hat, attributes)

    return sk, pk


def sign(
    sk: SecretKey,
    msgs: List[bytes]
) -> Signature:

    if len(sk.y) != len(msgs):
        raise ValueError(
            "Secret key attributes and messages should have same length")
    for msg in msgs:
        if not isinstance(jsonpickle.decode(msg), Bn):
            raise TypeError("Messages should be json encoded integers")

    h = G1.generator()
    exponent = sum(y_i * jsonpickle.decode(msg)
                   for y_i, msg in zip(sk.y, msgs)) + sk.x
    s2 = h**exponent

    return Signature(h, s2)


def verify(
    pk: PublicKey,
    signature: Signature,
    msgs: List[bytes]
) -> bool:

    if len(pk.Y) != len(msgs):
        raise ValueError(
            "Secret key attributes and messages should have same length")

    for msg in msgs:
        if not isinstance(jsonpickle.decode(msg), Bn):
            raise TypeError("Messages should be json encoded integers")

    s1, s2 = signature.sigma
    if s1 == G1.unity():
        return False

    Y_hat_m = [Y_hat_i ** jsonpickle.decode(msg)
               for Y_hat_i, msg in zip(pk.Y_hat, msgs)]
    product = pk.X_hat * G2.prod(Y_hat_m)

    return s1.pair(product) == s2.pair(pk.g_hat)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
    pk: PublicKey, user_attributes: AttributeMap
) -> Tuple[Tuple[Bn, AttributeMap], IssueRequest]:

    t = G1.order().random()
    state = (t, user_attributes)

    c = (pk.g**t) * G1.prod([pk.Y[i - 1] ** user_attributes[i]
                             for i in user_attributes.keys()])
    kp = createReqProof(pk, t, user_attributes, c)
    if len(user_attributes) == 0:
        return state, IssueRequest(pk.g**t, kp)
    return state, IssueRequest(c, kp)


def sign_issue_request(
    sk: SecretKey,
    pk: PublicKey,
    request: IssueRequest,
    issuer_attributes: AttributeMap
) -> BlindSignature:

    if not verifyReq(pk, request):
        raise ValueError("Invalid issue request")

    u = G1.order().random()
    g_exp_u = pk.g ** u

    if len(issuer_attributes) == 0:
        return BlindSignature(g_exp_u, (sk.X * request.c) ** u, issuer_attributes)

    s2_p = (sk.X * request.c *
            G1.prod([pk.Y[i - 1] ** issuer_attributes[i] for i in issuer_attributes.keys()]))**u
    return BlindSignature(g_exp_u, s2_p, issuer_attributes)


def obtain_credential(
    pk: PublicKey,
    response: BlindSignature,
    state: Tuple[Bn, AttributeMap]
) -> AnonymousCredential:

    t, user_attributes = state

    if len(pk.Y) != len(user_attributes) + len(response.issuerAttributes):
        raise ValueError(
            "The public key is configured for a different number of attributes"
        )

    s1_p, s2_p = response.sigma
    sigma = Signature(s1_p, s2_p / (s1_p ** t))

    sorted_all_attributes = dict(
        sorted((user_attributes | response.issuerAttributes).items())
    )
    if not verify(pk, sigma, toByte(sorted_all_attributes)):
        raise ValueError(
            "The signature is not valid for the given public key and attributes"
        )
    return AnonymousCredential(sigma, sorted_all_attributes)


## SHOWING PROTOCOL ##

def create_disclosure_proof(
    pk: PublicKey,
    credential: AnonymousCredential,
    hidden_attributes: AttributeMap,
    message: bytes,
) -> DisclosureProof:

    sortedH = dict(sorted(hidden_attributes.items()))

    r, t, t_r = GT.order().random(), GT.order().random(), GT.order().random()

    s1, s2 = credential.signature.sigma
    s1_p, s2_p = s1**r, (s2*(s1**t))**r
    sigma_p = Signature(s1_p, s2_p)

    r = s1_p.pair(pk.g_hat) ** t_r
    c = s1_p.pair(pk.g_hat) ** t

    if len(sortedH) > 0:
        a_i_p = [GT.order().random()
                 for _ in range(len(sortedH))]

        r = r*GT.prod([s1_p.pair(pk.Y_hat[i - 1]) ** a_i_p[ai_index]
                      for ai_index, i in enumerate(sortedH.keys())])

        c = c*GT.prod([s1_p.pair(pk.Y_hat[i - 1]) ** sortedH[i]
                      for i in sortedH.keys()])

    challenge = Bn.from_hex(
        sha256(jsonpickle.encode((pk.pk, c, r, message)).encode()).hexdigest()
    ).mod(GT.order())

    r0 = t_r - challenge * t
    response_index = []
    if len(sortedH) > 0:
        response_index = zip([rnd - challenge * attr for rnd,
                             attr in zip(a_i_p, sortedH.values())], sortedH.keys())

    return DisclosureProof(sigma_p, NonInteractiveProof(challenge, r0, response_index))


def verify_disclosure_proof(
    pk: PublicKey,
    disclosure_proof: DisclosureProof,
    disclosed_attributes: AttributeMap,
    message: bytes,
) -> bool:
    s1_p, s2_p = disclosure_proof.signature.sigma
    if s1_p == G1.unity:
        return False

    sortedD = dict(sorted(disclosed_attributes.items()))

    if len(sortedD) > 0:
        com = (s2_p.pair(pk.g_hat) * GT.prod([s1_p.pair(pk.Y_hat[i - 1])
               ** -sortedD[i]for i in sortedD.keys()])) / s1_p.pair(pk.X_hat)
    else:
        com = (s2_p.pair(pk.g_hat) * GT.prod([])) / s1_p.pair(pk.X_hat)

    R_p = com**disclosure_proof.pi.challenge * \
        s1_p.pair(pk.g_hat) ** disclosure_proof.pi.response_0

    R_p = R_p * GT.prod([s1_p.pair(pk.Y_hat[index - 1]) **
                        resp for (resp, index) in disclosure_proof.pi.response_index])

    # Compute challenge of R'
    challenge_prime = Bn.from_hex(
        sha256(jsonpickle.encode(
            (pk.pk, com, R_p, message)).encode()).hexdigest()
    ).mod(GT.order())

    return disclosure_proof.pi.challenge == challenge_prime


####################
## HELPER METHODS ##
####################

def createReqProof(
    pk: PublicKey, t: Bn, user_attributes: AttributeMap, com: G1Element
) -> NonInteractiveProof:

    r = G1.order().random()
    R = pk.g ** r
    sorted_user_attributes = dict(sorted(user_attributes.items()))
    if len(user_attributes) > 0:
        rElems = [G1.order().random() for _ in range(len(user_attributes))]
        R *= G1.prod([pk.Y[i - 1] ** rElems[j]
                     for j, i in enumerate(sorted_user_attributes.keys())])

    challenge = Bn.from_hex(
        sha256(jsonpickle.encode((pk.pk, R, com)).encode()).hexdigest()
    ).mod(G1.order())

    r0 = r - challenge * t
    response_index = []
    if len(user_attributes) > 0:
        response_index = zip([rnd - challenge * attr for rnd, attr in zip(
            rElems, sorted_user_attributes.values())], sorted_user_attributes.keys())

    return NonInteractiveProof(challenge, r0, response_index)


def verifyReq(
    pk: PublicKey, issue_req: IssueRequest
) -> bool:

    c, pi = issue_req.c, issue_req.pi
    R_prime = c**pi.challenge * pk.g**pi.response_0
    if len(pi.response_index) > 0:
        R_prime *= G1.prod(
            [pk.Y[index - 1] ** resp for resp, index in pi.response_index]
        )
    challenge_prime = Bn.from_hex(
        sha256(jsonpickle.encode((pk.pk, R_prime, c)).encode()).hexdigest()
    ).mod(G1.order())
    return pi.challenge == challenge_prime


def toByte(attributes: AttributeMap) -> List[bytes]:
    return [jsonpickle.encode(value) for value in dict(sorted(attributes.items())).values()]
