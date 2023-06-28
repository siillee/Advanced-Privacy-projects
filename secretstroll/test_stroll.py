import pytest

from credential import *
from stroll import *

###########
## TESTS ##
###########


def test_ca_generation():
    server = Server()
    client = Client()
    subscriptions = ["hockey", "football", "soccer", "basketball", "baseball"]
    sk, pk = server.generate_ca(subscriptions)

    sk,pk = jsonpickle.decode(sk), jsonpickle.decode(pk)
    assert isinstance(sk, SecretKey) and isinstance(pk, PublicKey)

    # Check with all possible subscriptions
    msgs = [jsonpickle.encode(client.secret).encode()]
    msgs += [jsonpickle.encode(toAttribute(sub)).encode() for sub in subscriptions]
    assert verify(pk, sign(sk, msgs), msgs)

    # Check with some subscriptions
    msgs = [jsonpickle.encode(client.secret).encode()]
    msgs += [jsonpickle.encode(toAttribute(sub)).encode() for sub in subscriptions[:3]]
    while len(msgs) < len(subscriptions) + 1:
        msgs += [jsonpickle.encode(toAttribute("None")).encode()]
    assert verify(pk, sign(sk, msgs), msgs)



def test_request_sign():
    server = Server()
    client = Client()
    subcriptions = ["bars", "restaurants", "cinemas", "museums", "theaters"]
    sk, pk = server.generate_ca(subcriptions)
    selectedSubscriptions = ["cinemas", "museums", "theaters"]
    userRequest, state = client.prepare_registration(pk, "Mike", selectedSubscriptions)
    serverSign = server.process_registration(
        sk, pk, userRequest, "Mike", selectedSubscriptions
    )
    credentials = client.process_registration_response(pk, serverSign, state)
    disclosedSub = ["cinemas", "museums"]

    msg = "this_is_a_msg".encode()
    client.sign_request(pk, credentials, msg, disclosedSub)




def test_check_signature():
    server = Server()
    client = Client()
    subscriptions = ["ballet", "opera", "theater", "concert", "museum"]
    sk, pk = server.generate_ca(subscriptions)
    selectedSubscriptions = ["ballet", "opera"]
    userReq, state = client.prepare_registration(pk, "Jhon", selectedSubscriptions)
    serverSign = server.process_registration(
        sk, pk, userReq, "Jhon", selectedSubscriptions
    )
    cred = client.process_registration_response(pk, serverSign, state)
    
    # Check with only one subscription
    disclosedSub = ["opera"]
    msg = "this_is_a_msg".encode()
    signature = client.sign_request(pk, cred, msg, disclosedSub)
    assert server.check_request_signature(pk, msg, disclosedSub, signature)
    
    # Check with all subscriptions
    disclosedSub = ["opera","ballet"]
    signature = client.sign_request(pk, cred, msg, disclosedSub)
    assert server.check_request_signature(pk, msg, disclosedSub, signature)

    # Check with no subscriptions, valid.
    disclosedSub = ["None"]
    signature = client.sign_request(pk, cred, msg, disclosedSub)
    assert server.check_request_signature(pk, msg, disclosedSub, signature)


    ############################
    # Check with invalid values #
    ############################

    # Check with no subscriptions, invalid.
    disclosedSub = []
    signature = client.sign_request(pk, cred, msg, disclosedSub)
    with pytest.raises(ValueError):
        server.check_request_signature(pk, msg, disclosedSub, signature)

    # Check with invalid subscriptions, invalid 
    disclosedSub = ["bars"]
    signature = client.sign_request(pk, cred, msg, disclosedSub)
    with pytest.raises(ValueError):
        server.check_request_signature(pk, msg, disclosedSub, signature)

    
