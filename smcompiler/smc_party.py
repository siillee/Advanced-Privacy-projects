"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

import collections
import json
from typing import (
    Dict,
    Set,
    Tuple,
    Union, 
    List
)

from communication import Communication
from expression import (
    Expression,
    Secret, 
    Scalar,
    AddOp, 
    SubOp, 
    MultOp
)
from protocol import ProtocolSpec
from secret_sharing import(
    reconstruct_secret,
    share_secret,
    Share,
)

# Feel free to add as many imports as you want.
import jsonpickle
import time
import csv

class SMCParty:
    """
    A client that executes an SMC protocol to collectively compute a value of an expression together
    with other clients.

    Attributes:
        client_id: Identifier of this client
        server_host: hostname of the server
        server_port: port of the server
        protocol_spec (ProtocolSpec): Protocol specification
        value_dict (dict): Dictionary assigning values to secrets belonging to this client.
    """

    def __init__(
            self,
            client_id: str,
            server_host: str,
            server_port: int,
            protocol_spec: ProtocolSpec,
            value_dict: Dict[Secret, int]
        ):
        self.comm = Communication(server_host, server_port, client_id)

        self.client_id = client_id
        self.protocol_spec = protocol_spec
        self.value_dict = value_dict

        self.secret_shares_received = {}
        self.client_zero = sorted(self.protocol_spec.participant_ids)[
            0] 

    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """

        startTime = time.time()

        # Sending shares of my secret to other clients.
        # First we compute shares for all secrets that this client has, then we send the appropriate shares to other clients. 
        num_of_shares = len(self.protocol_spec.participant_ids)
        for secretObj, value in self.value_dict.items():
            my_secret_shares = share_secret(value, num_of_shares)
            for i, client in enumerate(self.protocol_spec.participant_ids):
                self.comm.send_private_message(client, secretObj.id, my_secret_shares[i].serialize())
        
        # Processing the expression and returning the reconstructed result.
        res_share: Share = self.process_expression(self.protocol_spec.expr)

        # Writing performance measurements to file
        endTime = time.time()
        totalTime = endTime - startTime
        compTime = totalTime -self.comm.network_delay
        total_bytes_sent = self.comm.bytes_sent
        total_bytes_received = self.comm.bytes_received

        if self.client_id == self.client_zero:
            data = ["", totalTime, compTime, total_bytes_sent, total_bytes_received]
            with open('performance_data.csv', 'a', encoding='UTF8') as f:
                writer = csv.writer(f)
                writer.writerow(data)

        return self.reconstruction_of_secret("public_res", res_share)

    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression
        ) -> Share:
        if isinstance(expr, AddOp):
            a = self.process_expression(expr.a)
            b = self.process_expression(expr.b)

            if (isinstance(a, Share) and isinstance(b, Share)) or (isinstance(a, int) and isinstance(b, int)):
                return a + b 
            
            # In case a or b is a Scalar, only one client adds the Scalar. TODO: This is checked kinda stupidly, idk if there is a smarter way for now. 
            if self.client_id != "Alice":
                if isinstance(a, int):
                    return b
                return a
            
            return a + b

        if isinstance(expr, SubOp):
            a = self.process_expression(expr.a)
            b = self.process_expression(expr.b)
            
            if (isinstance(a, Share) and isinstance(b, Share)) or (isinstance(a, int) and isinstance(b, int)):
                return a - b
            
            if self.client_id != self.client_zero:
                if isinstance(a, int):
                    return -b
                return a
            
            return a - b
        
        if isinstance(expr, MultOp):
            a = self.process_expression(expr.a)
            b = self.process_expression(expr.b)

            # Case where both are of type Share. Get the beaver triplet shares, and do the computation needed.
            # Names of the variables are similar to how they named them in the docs on git. 
            if isinstance(a, Share) and isinstance(b, Share):
                beaver_triplet_shares = self.get_beaver_triplet(expr.id)
                x_a_share = a - beaver_triplet_shares[0]
                y_b_share = b - beaver_triplet_shares[1]

                x_a = self.reconstruction_of_secret("public_x_a_share", x_a_share)
                y_b = self.reconstruction_of_secret("public_y_b_share", y_b_share)

                z_share = beaver_triplet_shares[2] + (a*y_b) + (b*x_a)
                if self.client_id == self.client_zero:
                    z_share = z_share - (x_a*y_b)

                return z_share

            return a * b
             

        if isinstance(expr, Secret):
            if expr.id in self.secret_shares_received:
                return self.secret_shares_received[expr.id]
            else:
                self.secret_shares_received[expr.id] = Share.deserialize(
                    self.comm.retrieve_private_message(expr.id))
                return self.secret_shares_received[expr.id]

        if isinstance(expr, Scalar):
            return expr.value
        #
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.
        pass

    # Feel free to add as many methods as you want.    
    
    def get_beaver_triplet(self, id: str):
        return self.comm.retrieve_beaver_triplet_shares(id)
    
    def reconstruction_of_secret(self, label: str, myShare: Share) -> int: 

        res_secret_shares = []
        self.comm.publish_message(label, myShare.serialize())
        for client in self.protocol_spec.participant_ids:
            res_secret_shares.append(Share.deserialize(self.comm.retrieve_public_message(client, label)))

        return reconstruct_secret(res_secret_shares)