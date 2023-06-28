"""
Classes that you need to complete.
"""

from typing import List, Tuple
from petrelic.bn import Bn

from credential import *

# Optional import
from serialization import jsonpickle

# Type aliases
State = Tuple[Tuple[Bn, AttributeMap], str]

PRIVATE_ATTR_COUNT = 1


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """

    @staticmethod
    def generate_ca(
        subscriptions: List[str]
    ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        attributes = [toAttribute(x) for x in ["None"] + sorted(subscriptions)]
        sk, pk = generate_key(attributes)

        return jsonpickle.encode(sk).encode(), jsonpickle.encode(pk).encode()

    def process_registration(
        self,
        server_sk: bytes,
        server_pk: bytes,
        issuance_request: bytes,
        username: str,
        subscriptions: List[str]
    ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        sk, pk, issue_req = jsonpickle.decode(server_sk), jsonpickle.decode(
            server_pk), jsonpickle.decode(issuance_request)
        if not all(isinstance(obj, cls) for obj, cls in zip([sk, pk, issue_req], [SecretKey, PublicKey, IssueRequest])):
            raise TypeError("Invalid type for one of the arguments")

        if not isValidSubscription(pk, subscriptions):
            raise ValueError("Invalid subscriptions")

        blind_sign = sign_issue_request(
            sk, pk, issue_req, buildIssuerAttr(pk, subscriptions))
        return jsonpickle.encode(blind_sign, keys=True).encode()

    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
    ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        pk, disc_proof = jsonpickle.decode(
            server_pk), jsonpickle.decode(signature, keys=True)
        if not all(isinstance(obj, cls) for obj, cls in zip([pk, disc_proof], [PublicKey, DisclosureProof])):
            raise TypeError("Invalid type for one of the arguments")

        if not isValidSubscription(pk, revealed_attributes):
            raise ValueError("Invalid subscriptions")

        return verify_disclosure_proof(pk, disc_proof, buildDisclosedAttr(pk, revealed_attributes), message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        self.secret = G1.order().random()

    def prepare_registration(
        self,
        server_pk: bytes,
        username: str,
        subscriptions: List[str]
    ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        pk = jsonpickle.decode(server_pk)
        if not isinstance(pk, PublicKey):
            raise TypeError("Public key cannot be decoded")

        state, req = create_issue_request(pk, {1: self.secret})

        return jsonpickle.encode(req, keys=True).encode(), (state, username)

    def process_registration_response(
        self,
        server_pk: bytes,
        server_response: bytes,
        private_state: State
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        pk, signature = jsonpickle.decode(server_pk), jsonpickle.decode(server_response, keys=True)
        if not isinstance(pk, PublicKey) or not isinstance(signature, BlindSignature):
            raise TypeError("Inputs cannot be decoded")

        state0, _ = private_state

        return jsonpickle.encode(obtain_credential(pk, signature, state0), keys=True).encode()

    def sign_request(
        self,
        server_pk: bytes,
        credentials: bytes,
        message: bytes,
        types: List[str]
    ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        pk, cred = jsonpickle.decode(server_pk), jsonpickle.decode(credentials, keys=True)
        if not isinstance(pk, PublicKey) or not isinstance(cred, AnonymousCredential):
            raise TypeError("Inputs cannot be decoded")


        hidden_attributes = {
            i: attr
            for i, attr in cred.attributes.items()
            if (i, attr) not in buildDisclosedAttr(pk, types).items()
        }
        disclosure_proof = create_disclosure_proof(
            pk, cred, hidden_attributes, message)

        return jsonpickle.encode(disclosure_proof, keys=True).encode()


# Helper functions

def isValidSubscription(pk: PublicKey, subscriptions: List[str]) -> bool:
    return len(subscriptions) > 0 and all(
        toAttribute(subscr) in pk.attr for subscr in subscriptions
    )


def buildDisclosedAttr(
    pk: PublicKey, chosen_subscriptions: List[str]
) -> AttributeMap:
    all_subscriptions_map = all_subscriptions_attribute_map(pk)
    chosen_subscriptions_attributes = [
        toAttribute(x) for x in chosen_subscriptions]
    return {
        i: subscr
        for i, subscr in all_subscriptions_map.items()
        if subscr in chosen_subscriptions_attributes
    }


def buildIssuerAttr(
    pk: PublicKey, chosen_subscriptions: List[str]
) -> AttributeMap:
    all_subscriptions_map = all_subscriptions_attribute_map(pk)
    chosen_subscriptions_attributes = [
        toAttribute(x) for x in chosen_subscriptions]
    return {
        i: (
            subscr
            if subscr in chosen_subscriptions_attributes
            else toAttribute("None")
        )
        for i, subscr in all_subscriptions_map.items()
    }


def all_subscriptions_attribute_map(
    pk: PublicKey,
) -> AttributeMap:
    return {index + 1: attribute for index, attribute in enumerate(pk.attr) if index >= PRIVATE_ATTR_COUNT}


def toAttribute(subscription: str) -> Attribute:
    return Bn.from_binary(sha256(subscription.encode()).digest()).mod(G1.order())
