# -*- coding: utf-8 -*-

# http://domderrien.blogspot.com/2009/01/automatic-testing-of-gae-applications.html

import unittest
from signatures import *

class TestSignatures(unittest.TestCase):
  def __init__(self):
    self.id1 = "tag:example.org,2009:33293423947"
    self.ts1 = "2009-09-21T21:21:45.310021"
    self.au1 = "acct:test@example.com"
    self.id2 = "tag:example.org,2009:88782929991"
    self.ts2 = "2008-09-20T21:20:45.310021"
    self.au2 = "acct:jdoe@example.org"
    
    # Testing genSignature(id,parentid,timestamp,authoruri):
  def test_genSignature(self):
    """Verify that we get reasonable signatures for different types of input"""
    self.assertEqual(genSignature(self.id1,self.id2,self.ts1,self.au1),
                     genSignature(self.id1,self.id2,self.ts1,self.au1))
    self.assertNotEqual(genSignature(self.id1,self.id2,self.ts1,self.au1),
                     genSignature(self.id2,self.id1,self.ts1,self.au1))

if __name__ == "__main__":
  unittest.main()
