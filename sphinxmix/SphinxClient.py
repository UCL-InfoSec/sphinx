#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2016 George Danezis (UCL InfoSec Group)
#
# This file is part of Sphinx.
# 
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
# 
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.


from os import urandom
from collections import namedtuple
from struct import pack

from petlib.pack import encode, decode

# Python 2/3 compatibility
from builtins import bytes

from .SphinxParams import SphinxParams
from . import SphinxException


# FLAGS

#: Routing flag indicating message is to be relayed.
Relay_flag = "\xF0"

#: Routing flag indicating message is to be delivered.
Dest_flag = "\xF1"

#: Routing flag indicating surb reply is to be delivered.
Surb_flag = "\xF2"

# Padding/unpadding of message bodies: a 0 bit, followed by as many 1
# bits as it takes to fill it up

header_record = namedtuple("header_record", ["alpha", "s", "b", "aes"])

#: A helper named tuple to store PKI information.
pki_entry = namedtuple("pki_entry", ["id", "x", "y"])


def pad_body(msgtotalsize, body):
    """ Unpad the Sphinx message body."""
    body = body + b"\x7f"
    body = body + (b"\xff" * (msgtotalsize - len(body)))

    if (msgtotalsize - len(body)) < 0:
        raise SphinxException("Insufficient space for body") 

    return body

def unpad_body(body):
    """ Pad a Sphinx message body. """
    body = bytes(body)
    l = len(body) - 1
    x_marker = bytes(b"\x7f")[0]
    f_marker = bytes(b"\xff")[0]
    while body[l] == f_marker and l > 0:
        l -= 1
    
    if body[l] == x_marker:
        ret = body[:l]
    else:
        ret = b''
    
    return ret

# Prefix-free encoding/decoding of node names and destinations

# Sphinx nodes
def Nenc(idnum):
    """ The encoding of mix names. """
    return Route_pack((Relay_flag, idnum))

def Route_pack(info):
    return encode(info)

# Decode the prefix-free encoding.  Return the type, value, and the
# remainder of the input string
def PFdecode(param, packed):
    """ Decoder of prefix free encoder for commands received by mix or clients."""
    assert type(packed) is bytes
    return decode(packed)


def rand_subset(lst, nu):
    """Return a list of nu random elements of the given list (without
    replacement)."""

    # Randomize the order of the list by sorting on a random key
    nodeids = [(urandom(8),x) for x in lst]
    nodeids.sort(key=lambda x:x[0])

    # Return the first nu elements of the randomized list
    return list(map(lambda x:x[1], nodeids[:nu]))


def create_header(params, nodelist, keys, dest, assoc=None):
    """ Internal function, creating a Sphinx header.""" 

    node_meta = [pack("b", len(n)) + n for n in nodelist]
    
    if params.assoc_len > 0:
        assoc = assoc
    else:
        assoc = [b''] * len(nodelist)

    assert len(assoc) == len(nodelist)
    for assoc_data in assoc:
        assert len(assoc_data) == params.assoc_len

    p = params
    nu = len(nodelist)
    max_len = p.max_len
    
    group = p.group
    x = group.gensecret()

    blind_factors = [ x ]
    asbtuples = []
    
    from binascii import hexlify

    for k in keys:
        alpha = group.expon_base(blind_factors)
        
        s = group.expon(k, blind_factors)
        aes_s = p.get_aes_key(s)

        b = p.hb(aes_s)
        blind_factors += [ b ]

        hr = header_record(alpha, s, b, aes_s)
        asbtuples.append(hr)

    # Compute the filler strings
    phi = b''
    min_len = (max_len - 32)
    for i in range(1,nu):
        plain = phi + (b"\x00" * (p.k + len(node_meta[i])))

        kx = p.hrho(asbtuples[i-1].aes)
        mx = (b"\x00"*min_len)+plain

        phi = p.xor_rho(kx, mx)
        phi = phi[min_len:]

        min_len -= len(node_meta[i]) + p.k
        
    
    assert len(phi) == sum(map(len, node_meta[1:])) + (nu-1)*p.k

    # Compute the (beta, gamma) tuples
    # The os.urandom used to be a string of 0x00 bytes, but that's wrong
    
    final_routing = pack("b", len(dest)) + dest

    len_meta = sum(map(len, node_meta[1:]))
    random_pad_len = (max_len - 32) - len_meta - (nu-1)*p.k - len(final_routing)

    if random_pad_len < 0:
        raise SphinxException("Insufficient space routing info") 

    beta = final_routing + urandom(random_pad_len)
    beta = p.xor_rho(p.hrho(asbtuples[nu-1].aes), beta) + phi

    # Compute the MAC over the associated data and beta
    gamma = p.mu(p.hmu(asbtuples[nu-1].aes), assoc[nu-1] + beta)

    for i in range(nu-2, -1, -1):
        node_id = node_meta[i+1]

        plain_beta_len = (max_len - 32) - p.k - len(node_id)
        
        plain = node_id + gamma + beta[:plain_beta_len]
        
        beta = p.xor_rho(p.hrho(asbtuples[i].aes), plain)        
        gamma = p.mu(p.hmu(asbtuples[i].aes), assoc[i] + beta)        
        
    return (asbtuples[0].alpha, beta, gamma), \
        [x.aes for x in asbtuples]


def create_forward_message(params, nodelist, keys, dest, msg, assoc=None):
    """Creates a forward Sphix message, ready to be processed by a first mix. 

    It takes as parameters a node list of mix information, that will be provided to each mix, forming the path of the message;
    a list of public keys of all intermediate mixes; a destination and a message; and optinally an array of associated data (byte arrays)."""

    p = params
    # pki = p.pki
    nu = len(nodelist)
    assert len(dest) < 128 and len(dest) > 0
    assert p.k + 1 + len(dest) + len(msg) < p.m

    # Compute the header and the secrets

    final = Route_pack((Dest_flag, ))
    header, secrets = create_header(params, nodelist, keys, final, assoc)


    payload = pad_body(p.m - p.k, encode((dest, msg)))
    mac = p.mu(p.hpi(secrets[nu-1]), payload)
    body =  mac + payload

    # Compute the delta values
    delta = p.pi(p.hpi(secrets[nu-1]), body)
    for i in range(nu-2, -1, -1):
        delta = p.pi(p.hpi(secrets[i]), delta)

    return header, delta

def create_surb(params, nodelist, keys, dest, assoc=None):
    """Creates a Sphinx single use reply block (SURB) using a set of parameters;
    a sequence of mix identifiers; a pki mapping names of mixes to keys; and a final 
    destination. An array of associated data, for each mix on the path, may optionally
    be passed in.

    Returns:
        - A triplet (surbid, surbkeytuple, nymtuple). Where the surbid can be 
          used as an index to store the secrets surbkeytuple; nymtuple is the actual
          SURB that needs to be sent to the receiver.

    """
    p = params
    nu = len(nodelist)
    xid = urandom(p.k)

    # Compute the header and the secrets
    final = Route_pack((Surb_flag, dest, xid))
    header, secrets = create_header(params, nodelist, keys, final, assoc )

    ktilde = urandom(p.k)
    keytuple = [ktilde]
    keytuple.extend(map(p.hpi, secrets))
    return xid, keytuple, (nodelist[0], header, ktilde)

def package_surb(params, nymtuple, message):
    """Packages a message to be sent with a SURB. The message has to be bytes, 
    and the nymtuple is the structure returned by the create_surb call.

    Returns a header and a body to pass to the first mix.
    """
    n0, header0, ktilde = nymtuple

    message = pad_body(params.m - params.k, message)
    mac = params.mu(ktilde, message)
    body = params.pi(ktilde, mac + message )
    return (header0, body)


def receive_forward(params, mac_key, delta):
    """ Decodes the body of a forward message, and checks its MAC tag."""
    
    if delta[:params.k] != params.mu(mac_key, delta[params.k:]):
        raise SphinxException("Modified Body")

    delta = unpad_body(delta[params.k:])
    return decode(delta)

def receive_surb(params, keytuple, delta): 
    """Processes a SURB body to extract the reply. The keytuple was provided at the time of 
    SURB creation, and can be indexed by the SURB id, which is also returned to the receiving user.

    Returns the decoded message.
    """
    p = params
        
    ktilde = keytuple.pop(0)
    nu = len(keytuple)
    for i in range(nu-1, -1, -1):
        delta = p.pi(keytuple[i], delta)
    delta = p.pii(ktilde, delta)

    if delta[:p.k] == p.mu(ktilde, delta[p.k:]):
        msg = unpad_body(delta[p.k:])
    else:
        raise SphinxException("Modified SURB Body")
    
    return msg

def pack_message(params, m):
    """ A method to pack mix messages. """
    return encode(((params.max_len, params.m), m))

def unpack_message(params_dict, m):
    """ A method to unpack mix messages. """
    lens, msg = decode(m)
    if tuple(lens) not in params_dict:
        raise SphinxException("No parameter settings for: %s" % lens)
    return params_dict[tuple(lens)], msg

def test_timing(rep=100, payload_size=1024 * 10):
    r = 5
    params = SphinxParams(body_len=payload_size)
    pki = {}
    
    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i)
        x = params.group.gensecret()
        y = params.group.expon(params.group.g, [ x ])
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)

    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]
    print()
    
    import time
    t0 = time.time()
    for _ in range(rep):
        header, delta = create_forward_message(params, nodes_routing, node_keys, b"dest", b"this is a test")
    t1 = time.time()
    print("Time per mix encoding: %.2fms" % ((t1-t0)*1000.0/rep))
    T_package = (t1-t0)/rep

    from .SphinxNode import sphinx_process
    import time
    t0 = time.time()
    for _ in range(rep):
        x = pkiPriv[use_nodes[0]].x
        sphinx_process(params, x, header, delta)
    t1 = time.time()
    print("Time per mix processing: %.2fms" % ((t1-t0)*1000.0/rep))
    T_process = (t1-t0)/rep

    return T_package, T_process


def test_minimal():
    from .SphinxParams import SphinxParams
    r = 5

    params = SphinxParams()

    # The minimal PKI involves names of nodes and keys
    
    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i) # Nenc(params, bytes([i]))
        x = params.group.gensecret()
        y = params.group.expon(params.group.g, [ x ])
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)

    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]
    dest = b"bob"
    message = b"this is a test"
    header, delta = create_forward_message(params, nodes_routing, node_keys, dest, message)

    # Test encoding and decoding

    bin_message = pack_message(params, (header, delta))
    param_dict = { (params.max_len, params.m):params }

    px, (header1, delta1) = unpack_message(param_dict, bin_message)
    assert px == params
    assert header == tuple(header1)
    assert delta == delta1

    # Process message by the sequence of mixes
    from .SphinxNode import sphinx_process
    x = pkiPriv[use_nodes[0]].x

    i = 0
    while True:

        ret = sphinx_process(params, x, header, delta)
        (tag, B, (header, delta), mac_key) = ret
        routing = PFdecode(params, B)

        print("round %d" % i)
        i += 1

        # print("Type: %s" % typex)
        if routing[0] == Relay_flag:
            addr = routing[1]
            x = pkiPriv[addr].x 
        elif routing[0] == Dest_flag:
            assert len(routing) == 1
            # assert delta[:16] == b"\x00" * params.k
            dec_dest, dec_msg = receive_forward(params, mac_key, delta)
            assert dec_dest == dest
            assert dec_msg == message

            break
        else:
            print("Error")
            assert False
            break

    # Test the nym creation
    surbid, surbkeytuple, nymtuple = create_surb(params, nodes_routing, node_keys, b"myself")
    
    message = b"This is a reply"
    header, delta = package_surb(params, nymtuple, message)

    x = pkiPriv[use_nodes[0]].x

    while True:
        ret = sphinx_process(params, x, header, delta)
        (tag, B, (header, delta), mac_key) = ret
        routing = PFdecode(params, B)

        if routing[0] == Relay_flag:
            flag, addr = routing
            x = pkiPriv[addr].x 
        elif routing[0] == Surb_flag:
            flag, dest, myid = routing
            break

    received = receive_surb(params, surbkeytuple, delta)
    assert received == message

def test_assoc(rep=100, payload_size=1024 * 10):
    r = 5
    params = SphinxParams(body_len=payload_size, assoc_len=4)
    pki = {}
    
    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i)
        x = params.group.gensecret()
        y = params.group.expon(params.group.g, [ x ])
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)


    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]
    print()

    assoc = [b"XXXX"] * len(nodes_routing)
    
    import time
    t0 = time.time()
    for _ in range(rep):
        header, delta = create_forward_message(params, nodes_routing, node_keys, b"dest", b"this is a test", assoc)
    t1 = time.time()
    print("Time per mix encoding: %.2fms" % ((t1-t0)*1000.0/rep))
    T_package = (t1-t0)/rep

    from .SphinxNode import sphinx_process
    import time
    t0 = time.time()
    for _ in range(rep):
        x = pkiPriv[use_nodes[0]].x
        sphinx_process(params, x, header, delta, b"XXXX")
    t1 = time.time()
    print("Time per mix processing: %.2fms" % ((t1-t0)*1000.0/rep))
    T_process = (t1-t0)/rep

    return T_package, T_process

from nacl.bindings import crypto_scalarmult_base, crypto_scalarmult

def test_c25519(rep=100, payload_size=1024 * 10):
    r = 5
    from .SphinxParamsC25519 import Group_C25519
    
    group = Group_C25519()
    params = SphinxParams(group=group, body_len=payload_size, assoc_len=4)

    # Monkey patch to use AES-CTR
    params.lioness_enc = params.xor_rho
    params.lioness_dec = params.xor_rho


    pki = {}
    
    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i)
        x = params.group.gensecret()
        y = crypto_scalarmult_base(x)
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)


    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]
    print()

    assoc = [b"XXXX"] * len(nodes_routing)
    
    import time
    t0 = time.time()
    for _ in range(rep):
        header, delta = create_forward_message(params, nodes_routing, node_keys, b"dest", b"this is a test", assoc)
    t1 = time.time()
    print("Time per mix encoding: %.2fms" % ((t1-t0)*1000.0/rep))
    T_package = (t1-t0)/rep

    from .SphinxNode import sphinx_process
    import time
    t0 = time.time()
    for _ in range(rep):
        x = pkiPriv[use_nodes[0]].x
        sphinx_process(params, x, header, delta, b"XXXX")
    t1 = time.time()
    print("Time per mix processing: %.2fms" % ((t1-t0)*1000.0/rep))
    T_process = (t1-t0)/rep

    return T_package, T_process

def test_c25519_hemi(rep=1, payload_size=1024):
    r = 5
    from .SphinxParamsC25519 import Group_C25519
    
    group = Group_C25519()
    params = SphinxParams(group=group, body_len=payload_size, assoc_len=4)

    # Monkey patch to use AES-CTR
    params.lioness_enc = params.xor_rho
    params.lioness_dec = params.xor_rho


    pki = {}
    
    pkiPriv = {}
    pkiPub = {}

    for i in range(10):
        nid = pack("b", i) # Nenc(params, bytes([i]))
        x = params.group.gensecret()
        y = crypto_scalarmult_base(x)
        pkiPriv[nid] = pki_entry(nid, x, y)
        pkiPub[nid] = pki_entry(nid, None, y)


    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pkiPub.keys(), r)
    nodes_routing = list(map(Nenc, use_nodes))
    node_keys = [pkiPub[n].y for n in use_nodes]
    
    assoc = [b"XXXX"] * len(nodes_routing)
    
    header, delta = create_forward_message(params, nodes_routing, node_keys, b"dest", b"this is a test", assoc)
    

    from .SphinxNode import sphinx_process
    from binascii import hexlify

    x = pkiPriv[use_nodes[0]].x
    i = 0
    while True:
        assert pkiPriv[use_nodes[i]].x == x
        assert pkiPriv[use_nodes[i]].y == node_keys[i]

        alpha, beta, gamma = header

        (_, B, (header, delta), mac_key) = sphinx_process(params, x, header, delta, b"XXXX")

        routing = PFdecode(params, B)
        assert i == 4 or B == nodes_routing[i+1]
        
        i += 1

        if routing[0] == Relay_flag:
            addr = routing[1]
            assert addr == use_nodes[i]
            x = pkiPriv[addr].x
        elif routing[0] == Dest_flag:
            assert len(routing) == 1
            dec_dest, dec_msg = receive_forward(params, mac_key, delta)
            assert dec_dest == b"dest"
            assert dec_msg == b"this is a test"

            break
        else:
            print("Error")
            assert False
            break
        



if __name__ == "__main__":
    test_timing() 