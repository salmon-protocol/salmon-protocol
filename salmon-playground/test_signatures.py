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

#import urllib
#import httplib
#import hashlib
import unittest
import signatures
from base64 import b64encode

class TestValidSignature(unittest.TestCase):
  def setUp(self):
    self.test_private_cert = """
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
    self.test_public_key = ("0xB46230B021F628A6BABF1503BA95BDDAB17AF12" +
                           "E5245B82BED8A74C5E69D06C6F406BB93B7818CAD" +
                           "52FB42D89958CF2A52463571C31AECB9170FDDEEB" +
                           "8D527404B07EB9B3CAF2203F4F0DE12D081731144" +
                           "64575C29FC8A47EE41F8D44B5B9949AB5D2C1F359" +
                           "B2741113949848E861F8B70ADB0C9091D81C32FD7" +
                           "59782A806473")
  
  def test_rsa_signature(self):
    signer = signatures.Signer_RSA_SHA1(self.test_private_cert)
    validator = signatures.Validator_RSA_SHA1(self.test_public_key)
    text = unicode("One small splash for a salmon, one giant " +
                   "leap for salmonkind!","utf-8").encode("utf-8")
    sig = signer.sign(text)
    
    # The just-signed (text,sig) tuple should validate:
    self.assertTrue(validator.validate(text,sig))
    
    # Even tiny modifications to the text should not validate:
    self.assertFalse(validator.validate(text+'a',sig))
    
  