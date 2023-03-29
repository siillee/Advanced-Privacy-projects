import time
from multiprocessing import Process, Queue

import pytest

from expression import Scalar, Secret
from protocol import ProtocolSpec
from server import run

from smc_party import SMCParty


def smc_client(client_id, prot, value_dict, queue):
    cli = SMCParty(
        client_id,
        "localhost",
        5000,
        protocol_spec=prot,
        value_dict=value_dict
    )
    res = cli.run()
    queue.put(res)
    print(f"{client_id} has finished!")


def smc_server(args):
    run("localhost", 5000, args)


def run_processes(server_args, *client_args):
    queue = Queue()

    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=smc_client, args=(*args, queue)) for args in client_args]

    server.start()
    time.sleep(3)
    for client in clients:
        client.start()

    results = list()
    for client in clients:
        client.join()

    for client in clients:
        results.append(queue.get())

    server.terminate()
    server.join()

    # To "ensure" the workers are dead.
    time.sleep(2)

    print("Server stopped.")

    return results


def suite(parties, expr, expected):
    participants = list(parties.keys())

    prot = ProtocolSpec(expr=expr, participant_ids=participants)
    clients = [(name, prot, value_dict) for name, value_dict in parties.items()]

    results = run_processes(participants, *clients)

    for result in results:
        assert result == expected

def test_hospital_data():

    # Data of 2 patients per hospital, for three hospitals. One secret represents weight, the other 1/height^2 for each patient. 
    # In this case, the secrets represent: weight, 1/height^2, weight, 1/height^2.  
    hospital_1_data = [Secret(), Secret(), Secret(), Secret()]
    hospital_2_data = [Secret(), Secret(), Secret(), Secret()]
    hospital_3_data = [Secret(), Secret(), Secret(), Secret()]

    parties = {
        "Hospital 1": {hospital_1_data[0]: 82, hospital_1_data[1]: 0.3, hospital_1_data[2]: 75, hospital_1_data[3]: 0.27},
        "Hospital 2": {hospital_2_data[0]: 64, hospital_2_data[1]: 0.42, hospital_2_data[2]: 102, hospital_2_data[3]: 0.31}, 
        "Hospital 3": {hospital_3_data[0]: 105, hospital_3_data[1]: 0.28, hospital_3_data[2]: 53, hospital_3_data[3]: 0.35},
    }

    expr = (
         (hospital_1_data[0]*hospital_1_data[1]) + (hospital_1_data[2]*hospital_1_data[3]) + 
         (hospital_2_data[0]*hospital_2_data[1]) + (hospital_2_data[2]*hospital_2_data[3]) +
         (hospital_3_data[0]*hospital_3_data[1]) + (hospital_3_data[2]*hospital_3_data[3])    
        ) * (Scalar(1/12) + Scalar(1/12)) # TODO: This is stupidly artificial (instead of just having Scalar(1/6)), but for now we have scalar addition here :D
    
    expected = (82*0.3 + 75*0.27 + 64*0.42 + 102*0.31 + 105*0.28 + 53*0.35) * (1/12 + 1/12)
    suite(parties, expr, expected)
