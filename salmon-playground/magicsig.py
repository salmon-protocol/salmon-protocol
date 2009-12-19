#!/usr/bin/env python
#
# Copyright 2009 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Demonstrates magic signatures."""

import logging
import random
import datetime
import wsgiref.handlers
import dumper
import cgi
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import login_required
from google.appengine.ext.webapp import template
from google.appengine.ext import db
from google.appengine.api import users
import feedparser
import userdb

#Data model
#import model
#from model import Entry
#from signatures import *

from utils import *
import base64
import signatures

def create_magic_sig(text):
  """Creates a magic sig based on input text & current user."""
  the_private_cert = """
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
  # TODO: Get the private cert based on verifiable chain of evidence
  signer = signatures.Signer_RSA_SHA1(the_private_cert)
  B = base64.b64encode(unicode(text).encode("utf-8"))
  return dict(
    basetext = B,
    signature = signer.sign(B),
    algorithm = signer.get_name(),
    signatory = "TODO_userid",
  )


class SignThisHandler(webapp.RequestHandler):
  """Handles request to sign an Atom entry.

  Just a demo, that takes as input an arbitrary
  Atom entry and signs it (ultimately, using the
  currently authenticated user's key) and produces
  as output a Magic Signature.
  """

  @aclRequired
  def get(self):
    """Handles initial display of page."""
    headers = self.request.headers;
    logging.info('Headers =\n%s\n',headers)

    # TODO: Do a check for application/atom+xml and charset
    content_type = headers['Content-Type'];
    body = self.request.body.decode('utf-8')
    
    data = dict()
    self.response.out.write(template.render('magicsigdemo.html', data))
    self.response.set_status(200)

  @aclRequired
  def post(self):
    """Handles posting back of data and returns a result via XHR."""
    # TODO: Verify that current user session matches author of content, or throw error.
    data = self.request.get('data') 
    logging.info('data = %s\n',data)
    sig = create_magic_sig(data)
    logging.info('sig = %s\n',sig)

    #self.response.headers.add_header("Content-Type","text/xml; charset=utf-8")
    self.response.out.write("""
<?xml version='1.0' encoding='UTF-8'?>
<me:signed xmlns:me="http://salmon-protocol.org/ns/magic-signed">
  <data type="application/atom+xml">"""+sig['basetext']+"""</data>
  <alg>"""+sig['algorithm']+"""</alg>
  <sig>"""+sig['signature']+"""</sig>
<me:signed>
""")


if __name__ == '__main__':
  main()
