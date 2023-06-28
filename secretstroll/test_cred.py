import os
import random
from typing import List

import pytest

from petrelic.multiplicative.pairing import G1

from credential import *

L = 30


def test_key_generation(benchmark):
    attributes = [G1.order().random() for _ in range(L)]
    sK, pK = generate_key(attributes)
    benchmark(generate_key, attributes)

    assert isinstance(sK, SecretKey)
    assert isinstance(pK, PublicKey)

    assert len(sK.y) == L
    assert sK.X == pK.g ** sK.x

    assert pK.X_hat == pK.g_hat ** sK.x
    assert len(pK.Y) == L
    assert len(pK.attr) == L
    for y_i in sK.y:
        assert pK.g ** y_i in pK.Y
    for y_i in sK.y:
        assert pK.g_hat ** y_i in pK.Y_hat
    

def test_empty_key_generation():
    attributes = []
    with pytest.raises(ValueError):
        generate_key(attributes)

def test_negative_key_generation():
    attributes = [-G1.order().random() for _ in range(L)]
    with pytest.raises(TypeError):
        generate_key(attributes)


def test_sign():
    attributes = [G1.order().random() for _ in range(L)]
    sK, pK = generate_key(attributes)
    msgs = toByte(dict(enumerate(attributes)))
    sigma = sign(sK, msgs)


    assert verify(pK, sigma, msgs)


def test_sign_fail():
    attributes = [G1.order().random() for _ in range(L)]
    wrongAttributes = [str(G1.order().random()) for _ in range(L)]
    sK, pK = generate_key(attributes)
    msgs = toByte(dict(enumerate(attributes)))
    wrongMsgs = toByte(dict(enumerate(wrongAttributes)))
    sigma = sign(sK, msgs)

    with pytest.raises(TypeError):
        sign(sK, wrongMsgs)

    with pytest.raises(ValueError):
        verify(pK, sigma, [])

    assert not verify(pK, Signature(G1.unity(), G1.unity()), msgs)

    _, wrongPK = generate_key(attributes)
    assert not verify(wrongPK, sigma, msgs)



def test_issue_request(benchmark):
    attributes = [G1.order().random() for _ in range(L)]
    _, pK = generate_key(attributes)
    userAttributes, _ = randomAttributeMapping(attributes)
    create_issue_request(pK, userAttributes)
    benchmark(create_issue_request, pK, userAttributes)


def test_sign_issue_request(benchmark):
    attributes = [G1.order().random() for _ in range(L)]
    sK, pK = generate_key(attributes)
    userAttributes, issuerAttributes = randomAttributeMapping(attributes)
    _, issue_req = create_issue_request(pK, userAttributes)
    sign_issue_request(sK, pK, issue_req, issuerAttributes)
    benchmark(sign_issue_request, sK, pK, issue_req, issuerAttributes)



def test_verify_issue_request(benchmark):
    attributes = [G1.order().random() for _ in range(L)]
    _, pK = generate_key(attributes)
    userAttributes, _ = randomAttributeMapping(attributes)
    _, issueReq = create_issue_request(pK, userAttributes)
    assert verifyReq(pK,issueReq)
    benchmark(verifyReq, pK, issueReq)



def test_obtain_credential():
    attributes = [G1.order().random() for _ in range(L)]
    sK, pK = generate_key(attributes)
    userAttributes, issuerAttributes = randomAttributeMapping(attributes)

    state, issueReq = create_issue_request(pK, userAttributes)
    blindSignature = sign_issue_request(sK, pK, issueReq, issuerAttributes)
    obtain_credential(pK, blindSignature, state)



def test_disclosure_proof_verification():
    attributes = [G1.order().random() for _ in range(L)]
    sK, pK = generate_key(attributes)
    userAttributes, issuerAttributes = randomAttributeMapping(attributes)

    state, issueReq = create_issue_request(pK, userAttributes)
    blindSignature = sign_issue_request(sK, pK, issueReq, issuerAttributes)
    credentials = obtain_credential(pK, blindSignature, state)

    hiddenAttributes, disclosedAttributes = randomAttributeMapping(attributes)
    msg = os.urandom(10)

    disc_proof = create_disclosure_proof(pK, credentials, hiddenAttributes, msg)

    assert verify_disclosure_proof(pK, disc_proof, disclosedAttributes, msg)



def randomAttributeMapping(attributes: List[Attribute]) -> Tuple[AttributeMap, AttributeMap]:
    
    L = len(attributes)
    
    # Create a shuffled dictionary with keys in the range [1, L]
    shuffled_attributes = {i + 1: attribute for i, attribute in enumerate(attributes)}
    shuffled_keys = list(shuffled_attributes.keys())
    random.shuffle(shuffled_keys)
    
    # Determine the split index
    split_index = random.randint(0, L)
    
    # Split the shuffled attributes into two dictionaries
    user_attributes = {key: shuffled_attributes[key] for key in shuffled_keys[:split_index]}
    issuer_attributes = {key: shuffled_attributes[key] for key in shuffled_keys[split_index:]}
    
    return user_attributes, issuer_attributes


