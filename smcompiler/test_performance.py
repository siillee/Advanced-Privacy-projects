import time
from multiprocessing import Process, Queue

import pytest

from expression import Scalar, Secret
from protocol import ProtocolSpec
from server import run

from smc_party import SMCParty

from secret_sharing import Share

import csv


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


num_of_repeats = 10

def test_num_of_participants():

    for _ in range(num_of_repeats):
        with open('performance_data.csv', 'a', encoding='UTF8') as f:
            data = ["participants_test", "", "", "", ""]
            writer = csv.writer(f)
            writer.writerow(data)

        num_of_participants = [10, 20, 50, 100]
        alice_secret = Secret()
        bob_secret = Secret()
        charlie_secret = Secret()

        parties = {
            "Alice": {alice_secret: 3},
            "Bob": {bob_secret: 14},
            "Charlie": {charlie_secret: 2}
        }
        expr = (alice_secret + bob_secret + charlie_secret)
        expected = 3 + 14 + 2
    
        for num in num_of_participants:
            for i in range(num-3):
                id = "client" + str(i)
                new_secret = Secret()
                parties[id] = {new_secret: 1}

            suite(parties, expr, expected)

def test_addition():

    for _ in range(num_of_repeats):
        with open('performance_data.csv', 'a', encoding='UTF8') as f:
            data = ["add_test", "", "", "", ""]
            writer = csv.writer(f)
            writer.writerow(data)

        alice_secret = Secret()
        bob_secret = Secret()
        charlie_secret = Secret()

        parties = {
            "Alice": {alice_secret: 3},
            "Bob": {bob_secret: 14},
            "Charlie": {charlie_secret: 2}
        }

        num_of_additions = [10, 100, 250, 500]

        for num in num_of_additions:
            expr = alice_secret
            for _ in range(num-1):
                expr += alice_secret
            expected = num * 3
            suite(parties, expr, expected)

def test_scalar_addition():

    for _ in range(num_of_repeats):
        with open('performance_data.csv', 'a', encoding='UTF8') as f:
            data = ["scalar_add_test", "", "", "", ""]
            writer = csv.writer(f)
            writer.writerow(data)

        alice_secret = Secret()
        bob_secret = Secret()
        charlie_secret = Secret()

        parties = {
            "Alice": {alice_secret: 3},
            "Bob": {bob_secret: 14},
            "Charlie": {charlie_secret: 3}
        }
        
        num_of_additions = [10, 100, 250, 500]
        for num in num_of_additions:
            expr = (alice_secret + bob_secret + charlie_secret)
            for _ in range(num):
                expr += Scalar(5)
            expected = 20 + num*5
            suite(parties, expr, expected)

def test_multiplication():

    for _ in range(num_of_repeats):
        with open('performance_data.csv', 'a', encoding='UTF8') as f:
            data = ["mult_test", "", "", "", ""]
            writer = csv.writer(f)
            writer.writerow(data)

        alice_secret = Secret()
        bob_secret = Secret()
        charlie_secret = Secret()

        parties = {
            "Alice": {alice_secret: 3},
            "Bob": {bob_secret: 14},
            "Charlie": {charlie_secret: 2}
        }

        num_of_mults = [10, 100, 250, 500]

        for num in num_of_mults:
            expr = alice_secret
            for _ in range(num-1):
                expr *= alice_secret
            expected = (pow(3, num)) % Share.prime
            suite(parties, expr, expected)

def test_scalar_multiplication():

    for _ in range(num_of_repeats):
        with open('performance_data.csv', 'a', encoding='UTF8') as f:
            data = ["scalar_mult_test", "", "", "", ""]
            writer = csv.writer(f)
            writer.writerow(data)

        alice_secret = Secret()
        bob_secret = Secret()
        charlie_secret = Secret()

        parties = {
            "Alice": {alice_secret: 3},
            "Bob": {bob_secret: 14},
            "Charlie": {charlie_secret: 3}
        }
        
        num_of_mults = [10, 100, 250, 500]
        for num in num_of_mults:
            expr = (alice_secret + bob_secret + charlie_secret)
            for _ in range(num):
                expr *= Scalar(5)
            expected = (20 * pow(5, num)) % Share.prime
            suite(parties, expr, expected)