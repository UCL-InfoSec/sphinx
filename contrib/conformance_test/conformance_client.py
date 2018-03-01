from sphinxmix.SphinxClient import *
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxNode import sphinx_process

from petlib.bn import Bn
from petlib.ec import EcPt 

from base64 import b64decode

import sys

sphinx_params = SphinxParams()
args = sys.argv[1:]

dest = b64decode(args[0])
message = b64decode(args[1])

nodes_routing = []
node_keys = []
for node_key_pair in args[2:]:
    node_str, key_str = node_key_pair.split(':')

    node = Nenc(int(node_str))
    key = EcPt.from_binary(b64decode(key_str), sphinx_params.group.G)

    nodes_routing.append(node)
    node_keys.append(key)

header, delta = create_forward_message(sphinx_params, nodes_routing, node_keys, dest, message)
bin_message = pack_message(sphinx_params, (header, delta))

sys.stdout.buffer.write(bin_message)

