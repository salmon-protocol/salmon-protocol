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

import unittest
import signatures
from base64 import b64encode

import logging

class TestSignature(unittest.TestCase):

  _test_keypair = "mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q=="

  _test_publickey = "mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB"

  def setUp(self):
    # Well known keys to use for testing:
    self.signer = signatures.SignatureAlg_RSA_SHA1(self._test_keypair)
    self.verifier = signatures.SignatureAlg_RSA_SHA1(self._test_publickey)
  
  def test_rsa_signature(self):
    text = unicode("One small splash for a salmon, one giant " +
                   "leap for salmonkind!","utf-8").encode("utf-8")
    sig = self.signer.sign(text)
    
    # The just-signed (text,sig) tuple should validate:
    self.assertTrue(self.verifier.verify(text,sig))
    
    # Even tiny modifications to the text should not validate:
    self.assertFalse(self.verifier.verify(text+'a',sig))

  def test_serialization(self):
    self.assertEquals(self.signer.tostring(), self._test_keypair)
    self.assertEquals(self.verifier.tostring(), self._test_publickey)
    self.assertNotEquals(self.signer.tostring(), self.verifier.tostring())



