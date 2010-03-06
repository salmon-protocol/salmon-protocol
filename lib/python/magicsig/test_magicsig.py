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

"""Tests for magicsig.py."""

__author__ = 'jpanzer@google.com (John Panzer)'

import re
import unittest
import magicsig


def _StripWS(s):
  """Strips all whitespace from a string."""
  return re.sub('\s+', '', s)


class TestMagicEnvelopeProtocol(unittest.TestCase):
  """Tests Magic Envelope protocol."""

  class MockKeyRetriever(magicsig.PublicKeyRetriever):
    def LookupPublicKey(self, signer_uri=None):
      return  ('RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
               'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww=='
               '.AQAB'
               '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5'
               'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==')

  magicenv = None
  test_atom = """<?xml version='1.0' encoding='UTF-8'?>
    <entry xmlns='http://www.w3.org/2005/Atom'>
    <id>tag:example.com,2009:cmt-0.44775718</id>
      <author><name>test@example.com</name><uri>acct:test@example.com</uri>
      </author>
      <content>Salmon swim upstream!</content>
      <title>Salmon swim upstream!</title>
      <updated>2009-12-18T20:04:03Z</updated>
    </entry>
  """

  test_atom_multi_author = """<?xml version='1.0' encoding='UTF-8'?>
    <entry xmlns='http://www.w3.org/2005/Atom'>
    <id>tag:example.com,2009:cmt-0.44775718</id>
      <author><name>alice@example.com</name><uri>acct:alice@example.com</uri>
      </author>
      <author><name>bob@example.com</name><uri>acct:bob@example.com</uri>
      </author>
      <content>Salmon swim upstream!</content>
      <title>Salmon swim upstream!</title>
      <updated>2009-12-18T20:04:03Z</updated>
    </entry>
  """

  def setUp(self):
    self.magicenv = magicsig.MagicEnvelopeProtocol()
    self.magicenv.key_retriever = self.MockKeyRetriever()

  def testSignMessage(self):
    me = self.magicenv.SignMessage(self.test_atom,
                                   'application/atom+xml',
                                   'acct:test@example.com')

    self.assertTrue(me.has_key('data'))
    self.assertTrue(me.has_key('encoding'))
    self.assertTrue(me.has_key('sig'))
    self.assertTrue(me.has_key('alg'))

    self.assertTrue(self.magicenv.Verify(me))

  def testParse(self):
    me1 = self.magicenv.SignMessage(self.test_atom,
                                    'application/atom+xml',
                                    'acct:test@example.com')
    text = self.magicenv.Unfold(me1)

    me2 = self.magicenv.Parse(text)

    # Re-parsing the signed data should yield the same envelope bits:
    self.assertEquals(me1['data'], me2['data'])
    self.assertEquals(me1['sig'], me2['sig'])

  def testGetFirstAuthor(self):
    # Trival case of one author:
    a = self.magicenv.GetFirstAuthor(self.test_atom)
    self.assertEquals(a, 'acct:test@example.com')

    # Multi author case:
    a = self.magicenv.GetFirstAuthor(self.test_atom_multi_author)
    self.assertEquals(a, 'acct:alice@example.com')

  def testCheckAuthorship(self):
    # Check that we can recognize the author
    self.assertTrue(self.magicenv.CheckAuthorship(self.test_atom,
                                                  'acct:test@example.com'))

    # CheckAuthorship requires a real URI
    self.assertFalse(self.magicenv.CheckAuthorship(self.test_atom,
                                                   'test@example.com'))

    # We recognize only the first of multiple authors
    self.assertTrue(self.magicenv.CheckAuthorship(self.test_atom_multi_author,
                                                  'acct:alice@example.com'))
    self.assertFalse(self.magicenv.CheckAuthorship(self.test_atom_multi_author,
                                                   'acct:bob@example.com'))

  def testNormalizeUserIds(self):
    id1 = 'http://example.com'
    id2 = 'https://www.example.org/bob'
    id3 = 'acct:bob@example.org'
    em3 = 'bob@example.org'

    self.assertEquals(magicsig.NormalizeUserIdToUri(id1), id1)
    self.assertEquals(magicsig.NormalizeUserIdToUri(id2), id2)
    self.assertEquals(magicsig.NormalizeUserIdToUri(id3), id3)
    self.assertEquals(magicsig.NormalizeUserIdToUri(em3), id3)
    self.assertEquals(magicsig.NormalizeUserIdToUri(' '+id1+' '), id1)


if __name__ == '__main__':
  unittest.main()
