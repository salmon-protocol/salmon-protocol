#!/usr/bin/python
#
# Copyright 2009 Google Inc. All Rights Reserved.
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

"""Magic Signature implemenation for Salmon."""

__author__ = 'jpanzer@google.com (John Panzer)'


import base64
import re
import types

# PyCrypto: Note that this is not available in the
# downloadable GAE SDK, must be installed separately.
# See http://code.google.com/p/googleappengine/issues/detail?id=2493
# for why this is most easily installed under the 
# project's path rather than somewhere more sane.
import Crypto.PublicKey
import Crypto.PublicKey.RSA
from Crypto.Util import number

import hashlib


# Note that PyCrypto is a very low level library and its documentation
# leaves something to be desired.  As a cheat sheet, for the RSA
# algorithm, here's a decoding of terminology:
#     n - modulus (public)
#     e - public exponent
#     d - private exponent
#     (n, e) - public key
#     (n, d) - private key
#     (p, q) - the (private) primes from which the keypair is derived.

# Thus a public key is a tuple (n,e) and a public/private key pair
# is a tuple (n,e,d).  Often the exponent is 65537 so for convenience
# we default e=65537 in this code.


def GenSampleSignature(text):
  """Demo using a test public/private keypair."""
  demo_keypair = ('RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
                  'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww=='
                  '.AQAB'
                  '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5'
                  'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==')

  signer = SignatureAlgRsaSha1(demo_keypair)
  return signer.Sign(text)

# Algorithm generator (for testing only) TODO(jpanzer): Remove this?
#def GenerateSignatureAlg_RSA_SHA1():
#  logging.info("Module PublicKey = %s\n",Crypto.PublicKey)
#  keypair = Crypto.PublicKey.RSA.generate(512, os.urandom)
#  return SignatureAlg_RSA_SHA1((keypair.n,keypair.e,keypair.d))


# Utilities
def _NumToB64(num):
  """Turns a bignum into a urlsafe base64 encoded string."""
  return base64.urlsafe_b64encode(number.long_to_bytes(num))


def _B64ToNum(b64):
  """Turns a urlsafe base64 encoded string into a bignum."""
  return number.bytes_to_long(base64.urlsafe_b64decode(b64))


# Implementation of the Magic Envelope signature algorithm
class SignatureAlgRsaSha1(object):
  """Signature algorithm for RSA-SHA1 Magic Envelope."""

  def __init__(self, initializer):
    if isinstance(initializer, types.StringType):
      self.FromString(initializer)
    elif isinstance(initializer, types.TupleType):
      self.keypair = Crypto.PublicKey.RSA.construct(initializer)
    else:
      raise TypeError('Initializer must be string or tuple')

  def ToString(self, full_key_pair=True):
    """Serializes key to a safe string storage format.

    Args:
      full_key_pair: Whether to save the private key portion as well.
    Returns:
      The string representation of the key in the format:

        RSA.mod.exp[.optional_private_exp]

      Each component is a urlsafe-base64 encoded representation of
      the corresponding RSA key field.
    """
    mod = _NumToB64(self.keypair.n)
    exp = '.' + _NumToB64(self.keypair.e)
    private_exp = ''
    if full_key_pair and self.keypair.d:
      private_exp = '.' + _NumToB64(self.keypair.d)
    return 'RSA.' + mod + exp + private_exp

  def FromString(self, text):
    """Parses key from the standard string storage format.

    Args:
      text: The key in text form.  See ToString for description
        of expected format.
    Raises:
      ValueErrror: The input format was incorrect.
    """
    # First, remove all whitespace:
    text = re.sub('\s+', '', text)

    # Parse out the period-separated components
    key_regexp = 'RSA\.([^\.]+)\.([^\.]+)(.([^\.]+))?'
    m = re.match(key_regexp, text)
    if not m:
      raise ValueError('Badly formatted key string: '+text)

    (mod,exp) = m.group(1, 2)
    private_exp = ''
    if m.group(3):
      private_exp = m.group(4)
    self.keypair = Crypto.PublicKey.RSA.construct((_B64ToNum(mod),
                                                   _B64ToNum(exp),
                                                   _B64ToNum(private_exp) or
                                                   None))

  def GetName(self):
    return 'RSA-SHA1'

  def Sign(self, bytes_to_sign):
    """Signs the bytes and returns signature in base64 format."""
    # Expression should be:
    # b64(signature(sha1_digest(bytes_to_sign)))

    # Sign using the private key (PKCS1-SHA1 signature)
    sha1_hash_digest = hashlib.sha1(bytes_to_sign).digest()

    # Compute the signature:
    signature_long = self.keypair.sign(sha1_hash_digest, None)[0]
    signature_bytes = number.long_to_bytes(signature_long)
    return base64.urlsafe_b64encode(signature_bytes).encode('utf-8')

  def Verify(self, signed_bytes, signature_b64):
    """Determines the validity of a signature over a signed buffer of bytes.

    Args:
      signed_bytes: string The buffer of bytes the signature_b64 covers.
      signature_b64: string The putative signature, base64-encoded, to check.
    Returns:
      True if the request validated, False otherwise.
    """
    # Thing to verify is sha1_digest(signed_bytes)

    # Compute SHA1 digest of signed bytes; this is the actual signed thing:
    sha1_hash_digest = hashlib.sha1(signed_bytes).digest()

    # Get remote signature:
    remote_signature = base64.urlsafe_b64decode(signature_b64.encode('utf-8'))
    remote_signature = number.bytes_to_long(remote_signature)

    # Verify signature given public key:
    return self.keypair.verify(sha1_hash_digest, (remote_signature,))


# Data format notes:
# The basic idea is to wrap the content to be signed inside an "envelope"
# that allows the content to be passed through various systems un-munged.
# To this end, we construct an application/magic-envelope content type
# that can be used as-is or as part of other building blocks.  There
# are XML and JSON variants:

# Content-Type: application/magic-envelope+xml
#<?xml version='1.0' encoding='UTF-8'?>
#<me:env xmlns:me='http://salmon-protocol.org/ns/magic-env'>
#  <me:data type='application/atom+xml' encoding='base64'>PD94...A==</me:data>
#  <me:alg>RSA-SHA1</me:alg>
#  <me:sig>EvGSD2vi8qYcveHnb-rrlok07qnCXjn8YSeCDDXlbhILSabgvNsPpbe76up8w63i2fWHvLKJzeGLKfyHg8ZomQ==</me:sig>
#</me:env>

# Content-Type: application/magic-envelope+json
# [
#   {"data" : "PD94...A=="},
#   {"data.type": "application/atom+xml"},
#   {"data.encoding": "base64"},
#   {"alg": "RSA-SHA1"},
#   {"sig": "EvGSD2vi8qYcveHnb-rrlok07qnCXjn8YSeCDDXlbhILSabgvNsPpbe76up8w63i2fWHvLKJzeGLKfyHg8ZomQ=="},
# ]
  
# Content-Type: application/atom+xml
#<?xml version="1.0" encoding="utf-8"?><entry xmlns="http://www.w3.org/2005/Atom">
#  <id>tag:example.com,2009:cmt-0.44775718</id>  
#  <author><name>test@example.com</name><uri>acct:jpanzer@google.com</uri></author>
#  <thr:in-reply-to ref="tag:blogger.com,1999:blog-893591374313312737.post-3861663258538857954" xmlns:thr="http://purl.org/syndication/thread/1.0">tag:blogger.com,1999:blog-893591374313312737.post-3861663258538857954
#  </thr:in-reply-to>
#  <content>Salmon swim upstream!</content>
#  <title>Salmon swim upstream!</title>
#  <updated>2009-12-18T20:04:03Z</updated>
#  <me:provenance xmlns:me="http://salmon-protocol.org/ns/magic-env">
#    <me:data encoding="base64" type="application/atom+xml">PD94...A==</me:data>
#    <me:alg>RSA-SHA1</me:alg>
#    <me:sig>EvGSD2vi8qYcveHnb-rrlok07qnCXjn8YSeCDDXlbhILSabgvNsPpbe76up8w63i2fWHvLKJzeGLKfyHg8ZomQ==</me:sig>
#  </me:provenance>
#</entry>

# The Atom form is for use with legacy processors that do not understand 
# application/magic-envelope, or to expose data to a mixed audience
# of processers some of whom understand magic-envelope and some of whom
# cannot.  The bare form is preferred for brevity, simplicity, and security
# wherever possible.  It is legal and possible to create a <feed> which
# contains <me:env> elements, but they will only be understood by
# Magic Envelope-aware feed processors.

# To turn a signed-entry into an Atom entry for processing involves a simple
# intermediate step: entry = xml_parse(base64decode(envelope.data)).  
# Verifying that the signature is valid is more complicated.
