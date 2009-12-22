#!/usr/bin/python
#
# Copyright (C) 2009 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'jpanzer@google.com (John Panzer)'

"""Handles signature mechanisms for Salmon"""

import base64
import hashlib
import logging
import random
import dumper
import datetime

# PyCrypto: Note that this is not available in the
# downloadable GAE SDK, must be installed separately.
from Crypto.PublicKey import RSA
from Crypto.Util import number

# To start with, use gdata tlslite library for signing,
# TODO: Swap this out once we have working tests:
from gdata.tlslite.utils import keyfactory
from gdata.tlslite.utils import cryptomath

def genSignature(xml_buffer):
  """ Not the real signature algorithm, just a placeholder!!!  Do not use for anything serious!!! """
  cert = """
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----
"""
  signer = Signer_RSA_SHA1(cert)
  return signer.sign(xml_buffer)

# Implementation of the Magic Envelope signature algorithm

class Validator_RSA_SHA1:
  """Validator for the RSA-SHA1 signature algorithm.
     Given a public key, validates signed byte buffers.
  """
  def __init__(self, public_key_str, exponent=65537):
    """
    Creates a validator for the RSA-SHA1 signing mechanism.
    
    Args:
      public_key_str: string The RSA public key modulus, expressed in hex 
          format.  Typically, this will look something like: 
                0x00b1e057678343866db89d7dec2518
                99261bf2f5e0d95f5d868f81d600c9a1
                01c9e6da20606290228308551ed3acf9
                921421dcd01ef1de35dd3275cd4983c7
                be0be325ce8dfc3af6860f7ab0bf3274
                2cd9fb2fcd1cd1756bbc400b743f73ac
                efb45d26694caf4f26b9765b9f656652
                45524de957e8c547c358781fdfb68ec0
                56d1
      exponent: int The RSA public key exponent.
    """
    public_key_long = long(public_key_str, 16)
    self.public_key = RSA.construct((public_key_long, exponent))

  def validate(self, signed_bytes, signature_b64):
    """
    Determines the validity of a signature over a signed buffer of bytes.
    
    Args:
      signed_bytes: string The buffer of bytes the signature_b64 covers.
      signature_b64: string The putative signature, base64-encoded, to check.
      
    Returns: bool True if the request validated, False otherwise.
    """
    local_hash = hashlib.sha1(signed_bytes).digest()
      
    try:
      remote_signature = base64.urlsafe_b64decode(signature_b64.encode("utf-8"))
      remote_hash = self.public_key.encrypt(remote_signature, '')[0][-20:]
    except Exception, err:
      logging.exception('Error encrypting remote signature:')
      return False
      
    return local_hash == remote_hash


class Signer_RSA_SHA1:
  """Signer for the RSA-SHA1 signature algorithm.
     Given a private key, generates signature for an
     arbitrary byte buffer.
  """  
  def __init__(self, private_cert):
    self.privatekey = keyfactory.parsePrivateKey(private_cert)
  
  def get_name(self):
    return "RSA-SHA1"

  def sign(self, bytes_to_sign):
    # Sign using the private key (PKCS1-SHA1 signature)
    signature_bytes = self.privatekey.hashAndSign(bytes_to_sign)

    # Return signature base64-encoded
    return base64.urlsafe_b64encode(signature_bytes)

# Data format notes:
# The basic idea is to wrap the content to be signed inside an "envelope"
# that allows the content to be passed through various systems un-munged.
# To this end, we construct an application/magic-envelope content type
# that can be used as-is or as part of other building blocks.  There
# are XML and JSON variants:

# Content-Type: application/magic-signed+xml
# <me:signed xmlns:me="http://salmon-protocol.org/ns/magic-signed">
#   <data type="application/atom+xml">B</data>
#   <alg>RSA-SHA1</alg>
#   <sig>S</sig>
#   <signer>acct:bob@example.org></signer>
# <me:signed>

# Content-Type: application/magic-envelope+json
# [
#   {"data" : B},
#   {"data-type": "application/json"},
#   {"alg": "RSA-SHA1"},
#   {"sig": S},
#   {"signer": "acct:bob@example.org"}
# ]
  
# Content-Type: application/atom+xml
# <entry>
#   <id>some id</id>
#   <title>some title</title>
#   <author><url>acct:bob@example.org</url></author>
#   <updated>some timestamp</updated>
#   <content>possibly modified content goes here</content>
#   <me:signed>
#     <data type="application/atom+xml">B</data>
#     <alg>RSA-SHA1</alg>
#     <sig>S</sig>
#     <signer>acct:bob@example.org></signer>
#   <me:signed>
# </entry>

# The Atom form is for use with legacy processors that do not understand 
# application/magic-envelope, or to expose data to a mixed audience
# of processers some of whom understand magic-envelope and some of whom
# cannot.  The bare form is preferred for brevity, simplicity, and security
# wherever possible.  It is legal and possible to create a <feed> which
# contains <me:signed-entry> elements.  It is even useful.

# To turn a signed-entry into an Atom entry for processing involves a simple
# intermediate step: entry = xml_parse(base64decode(signed-entry.data)).  
# Verifying that the signature is valid is more complicated of course.


