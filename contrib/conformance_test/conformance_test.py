from sphinxmix.SphinxClient import *
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxNode import sphinx_process

from petlib.bn import Bn

from base64 import b64encode

import sys
import subprocess

pki_tuple = namedtuple('pki_tuple', ['id', 'private_key', 'public_key'])

def run_client_under_test(client_command, dest, message, use_nodes, node_keys):
    dest_encoded = b64encode(dest).decode()
    message_encoded = b64encode(message).decode()

    node_key_pairs = []
    for i in range(len(use_nodes)):
        pair = str(use_nodes[i]) + ':' + b64encode(node_keys[i].export()).decode()
        node_key_pairs.append(pair)

    run_command = []
    for command in client_command.split(' '):
        run_command.append(command)

    run_command.append(dest_encoded)
    run_command.append(message_encoded)

    for node_key_pair in node_key_pairs:
        run_command.append(node_key_pair)

    return subprocess.run(run_command, stdout=subprocess.PIPE).stdout


def initialise_pki(sphinx_params, num_mix_nodes):
    pki = {}

    for i in range(num_mix_nodes):
        node_id = i
        private_key = sphinx_params.group.gensecret()
        public_key = sphinx_params.group.expon(sphinx_params.group.g, [private_key])
        pki[node_id] = pki_tuple(node_id, private_key, public_key)

    return pki


def route_message_through_network(sphinx_params, pki, current_node_id, bin_message):
    param_dict = { (sphinx_params.max_len, sphinx_params.m): sphinx_params }
    _, (header, delta) = unpack_message(param_dict, bin_message)

    current_private_key = pki[current_node_id].private_key

    while True:
        ret = sphinx_process(sphinx_params, current_private_key, header, delta)
        (tag, B, (header, delta), mac_key) = ret
        routing = PFdecode(sphinx_params, B)

        if routing[0] == Relay_flag:
            current_node_id = routing[1]
            current_private_key = pki[current_node_id].private_key 
        elif routing[0] == Dest_flag:
            return receive_forward(sphinx_params, mac_key, delta)
        else:
            return None


def test_create_forward_message_creation(client_command, num_mix_nodes=10, num_path_nodes=5):
    sphinx_params = SphinxParams()

    pki = initialise_pki(sphinx_params, num_mix_nodes)

    use_nodes = rand_subset(pki.keys(), num_path_nodes)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pki[n].public_key for n in use_nodes]

    dest = b'bob'
    message = b'this is a test'

    bin_message = run_client_under_test(client_command, dest, message, use_nodes, node_keys)

    routing_result = route_message_through_network(sphinx_params, pki, use_nodes[0], bin_message)
    if routing_result:
        routed_dest, routed_message = routing_result

        if routed_dest == dest and routed_message == message:
            print('Success')
        else:
            print('Failure')
    else:
        print('Failure')


if __name__ == '__main__':
    test_create_forward_message_creation(sys.argv[1])

