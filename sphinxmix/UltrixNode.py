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


# Python 2/3 compatibility
from builtins import bytes

from . import SphinxException

# Core Process function -- devoid of any chrome
def ultrix_process(params, secret, header, delta, assoc=b''):
    """ The heart of a Ultrix server, that processes incoming messages.
    It takes a set of parameters, the secret of the server,
    and an incoming message header and body. Optinally some Associated
    data may also be passed in to check their integrity.
        
    """
    p = params
    group = p.group
    alpha, beta, gamma, dest_key = header
    original_beta = beta

    if params.assoc_len != len(assoc):
        raise SphinxException("Associated data length mismatch: expected %s and got %s." % (params.assoc_len, len(assoc)))

    # Check that alpha is in the group
    if not group.in_group(alpha):
        raise SphinxException("Alpha not in Group.")

    # Compute the shared secret
    s = group.expon(alpha, [ secret ])
    aes_s = p.get_aes_key(s)
    
    assert len(beta) == p.max_len - 32
    
    beta_pad = beta + (b"\x00" * (2 * p.max_len)) 
    B = p.xor_rho(p.hrho(aes_s), beta_pad)

    length = B[0]
    routing = B[1:1+length]
    rest = B[1+length:]

    tag = p.htau(aes_s)
    b = p.hb(alpha, aes_s)
    alpha = group.expon(alpha, [ b ])
    beta = rest[:(p.max_len - 32)]

    x_gamma = gamma
    gamma = p.mu(p.hmu(aes_s), original_beta)
    gamma2 = p.mu(p.hmu2(aes_s), original_beta)
    K = p.derive_key(aes_s, gamma)
    # delta = p.pii(p.hpi(K), delta)
    dest_key = p.small_perm(gamma2, dest_key)
    delta = p.xor_rho(p.hpi(K), delta)

    mac_key = p.hpi(K)
    ret = (tag, routing, ((alpha, beta, gamma, dest_key), delta), mac_key)
    return ret

