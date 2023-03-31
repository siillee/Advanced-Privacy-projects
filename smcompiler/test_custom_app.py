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
        print("Average BMI is : " + str(result/600))
        assert result == expected

# This test demonstrates a simple example of how hospitals can compute statistics in a privacy perserving manner. 
# The example consists of calculating the average BMI of patients in the hospitals. The expression evaluates the sum of the products of weight
# and height, and the average is calculated outside the expression, in the suite(...) function. This is because we do not have division
# implemented in this project. The reason for having the multiplications by 10 is to work with integers. 
def test_hospital_data():

    # Data of 2 patients per hospital, for three hospitals. One secret represents weight, the other 10/height^2 for each patient. 
    # In this case, the secrets represent: weight, 10/height^2, weight, 10/height^2.  
    hospital_1_data = [Secret(), Secret(), Secret(), Secret()]
    hospital_2_data = [Secret(), Secret(), Secret(), Secret()]
    hospital_3_data = [Secret(), Secret(), Secret(), Secret()]

    parties = {
        "Hospital 1": {hospital_1_data[0]: 80, hospital_1_data[1]: 3, hospital_1_data[2]: 75, hospital_1_data[3]: 2},
        "Hospital 2": {hospital_2_data[0]: 60, hospital_2_data[1]: 4, hospital_2_data[2]: 102, hospital_2_data[3]: 3}, 
        "Hospital 3": {hospital_3_data[0]: 100, hospital_3_data[1]: 2, hospital_3_data[2]: 53, hospital_3_data[3]: 3},
    }

    expr = (
         ((hospital_1_data[0] + Scalar(2))*hospital_1_data[1]*(Scalar(5) + Scalar(5))) + (hospital_1_data[2]*hospital_1_data[3]*(Scalar(5) + Scalar(5))) + 
         ((hospital_2_data[0] + Scalar(4))*hospital_2_data[1]*(Scalar(5) + Scalar(5))) + (hospital_2_data[2]*hospital_2_data[3]*(Scalar(5) + Scalar(5))) +
         ((hospital_3_data[0] + Scalar(5)) *hospital_3_data[1]*(Scalar(5) + Scalar(5))) + (hospital_3_data[2]*hospital_3_data[3]*(Scalar(5) + Scalar(5)))    
        )
    
    expected = (820*3 + 750*2 + 640*4 + 1020*3 + 1050*2 + 530*3) 
    suite(parties, expr, expected)
    