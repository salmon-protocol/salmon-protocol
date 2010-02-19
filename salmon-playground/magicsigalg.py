#!/usr/bin/python2.4
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

"""Implementation of Magic Signatures low level operations.

See Magic Signatures RFC for specification.  This implements
the cryptographic layer of the spec, essentially signing and
verifying byte buffers using a public key algorithm.
"""

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
  """Demo using a hard coded, test public/private keypair."""
  demo_keypair = ('RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
                  'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww=='
                  '.AQAB'
                  '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5'
                  'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==')

  signer = SignatureAlgRsaSha256(demo_keypair)
  return signer.Sign(text)


# Utilities
def _NumToB64(num):
  """Turns a bignum into a urlsafe base64 encoded string."""
  return base64.urlsafe_b64encode(number.long_to_bytes(num))


def _B64ToNum(b64):
  """Turns a urlsafe base64 encoded string into a bignum."""
  return number.bytes_to_long(base64.urlsafe_b64decode(b64))


# Implementation of the Magic Envelope signature algorithm
class SignatureAlgRsaSha256(object):
  """Signature algorithm for RSA-SHA256 Magic Envelope."""

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
      ValueError: The input format was incorrect.
    """
    # First, remove all whitespace:
    text = re.sub('\s+', '', text)

    # Parse out the period-separated components
    key_regexp = 'RSA\.([^\.]+)\.([^\.]+)(.([^\.]+))?'
    m = re.match(key_regexp, text)
    if not m:
      raise ValueError('Badly formatted key string: '+text)

    (mod, exp) = m.group(1, 2)
    private_exp = ''
    if m.group(3):
      private_exp = m.group(4)
    self.keypair = Crypto.PublicKey.RSA.construct((_B64ToNum(mod),
                                                   _B64ToNum(exp),
                                                   _B64ToNum(private_exp) or
                                                   None))

  def GetName(self):
    """Returns string identifier for algorithm used."""
    return 'RSA-SHA256'

  def Sign(self, bytes_to_sign):
    """Signs the bytes and returns signature in base64 format."""
    # Implements the expression:
    # b64(signature(sha256_digest(bytes_to_sign)))

    # Sign using the private key (PKCS1-SHA256 signature)
    sha256_hash_digest = hashlib.sha256(bytes_to_sign).digest()

    # Compute the signature:
    signature_long = self.keypair.sign(sha256_hash_digest, None)[0]
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
    # Thing to verify is sha256_digest(signed_bytes)

    # Compute SHA256 digest of signed bytes; this is the actual signed thing:
    sha256_hash_digest = hashlib.sha256(signed_bytes).digest()

    # Get remote signature:
    remote_signature = base64.urlsafe_b64decode(signature_b64.encode('utf-8'))
    remote_signature = number.bytes_to_long(remote_signature)

    # Verify signature given public key:
    return self.keypair.verify(sha256_hash_digest, (remote_signature,))
