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

from string import strip

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


# Just for bootstrapping, use test key:

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

the_public_key = ("0xB46230B021F628A6BABF1503BA95BDDAB17AF12" +
                    "E5245B82BED8A74C5E69D06C6F406BB93B7818CAD" +
                    "52FB42D89958CF2A52463571C31AECB9170FDDEEB" +
                    "8D527404B07EB9B3CAF2203F4F0DE12D081731144" +
                    "64575C29FC8A47EE41F8D44B5B9949AB5D2C1F359" +
                    "B2741113949848E861F8B70ADB0C9091D81C32FD7" +
                    "59782A806473")

def createMagicEnv(text):
  """Creates a magic envelope based on input text & current user.
     
  Note the importance of using the url-safe variant of base64
  encoding; without this, round trips through the Web are likely
  to result in subtle and hard to diagnose problems.  Specifically,
  this is standard base64 with - (dash) instead of + and _ (underscore)
  instead of '/'.
  """

  # TODO: Get the private cert based on verifiable chain of evidence
  signer = signatures.Signer_RSA_SHA1(the_private_cert)
  B = base64.urlsafe_b64encode(unicode(text).encode("utf-8")).encode("utf-8")

  return dict(
    data = B,
    encoding = "base64",
    sig = signer.sign(B),
    alg = signer.get_name(),
  )

def verifyMagicEnv(env):
  """Verifies a magic envelope (checks that its signature matches the
     contents)."""

  assert env['alg'] == "RSA-SHA1"
  assert env['encoding'] == "base64"
  validator = signatures.Validator_RSA_SHA1(the_public_key)

  logging.info("Verifying data:\n%s\n versus signature:\n%s\n",env['data'],env['sig'])

  return validator.validate(env['data'],env['sig'])


# TODO: Move this
from xml.dom.minidom import parse, parseString

def getSingleElementByTagNameNS(e, NS, tagName):
  seq = e.getElementsByTagNameNS(unicode(NS),unicode(tagName))
  #seq = e.getElementsByTagName(tagName)
  assert seq.length > 0
  assert seq.length == 1
  return seq.item(0)

def parseMagicEnv(textinput):
  """Parses a magic envelope from either application/magic-envelope
     or application/atom format. """

  NS = 'http://salmon-protocol.org/ns/magic-env'

  d = parseString(textinput)
  if d.documentElement.tagName == "entry":
    envEl = getSingleElementByTagNameNS(d,NS,"provenance")
  elif d.documentElement.tagName == "me:env":
    envEl = d.documentElement
  else:
    logging.error('Unknown input format; root element tag is %s\n',d.documentElement.tagName)
    raise unicode("Unrecognized input format")

  #for c in envEl.childNodes:
  #  logging.info('Child node: %s\n',c)
  #t = getSingleElementByTagNameNS(envEl,NS,'me:data')
  #for c in t.childNodes:
  #  logging.info('Child node of me:data: %s\n',c)
  #
  #logging.info('First child: %s\n',t.firstChild);

  logging.info('envEl = %s\n',envEl)

  dataEl = getSingleElementByTagNameNS(envEl,NS,'data')

  # Pull magic envelope fields out into dict. Don't forget
  # to remove leading and trailing whitepace from each field's
  # data.
  return dict (
    data = strip(dataEl.firstChild.data),
    encoding = strip(dataEl.getAttribute('encoding')),
    mimetype = strip(dataEl.getAttribute('type')),
    alg = strip(getSingleElementByTagNameNS(envEl,NS,'alg').firstChild.data),
    sig = strip(getSingleElementByTagNameNS(envEl,NS,'sig').firstChild.data),
  )


def unfoldMagicEnv(env):
  """Unfolds a magic envelope inside-out into (typically) an
     Atom Entry with an env:provenance extension element 
     for tracking the original magic signature."""
  d = parseString(base64.urlsafe_b64decode(env['data']))
  assert d.documentElement.tagName == "entry"

  # Create a provenance and add it in.  Note that support
  # for namespaces on output in minidom is even worse
  # than support for parsing, so we have to specify
  # the qualified name completely here for each element.
  NS = u'http://salmon-protocol.org/ns/magic-env'
  prov = d.createElementNS(NS,'me:provenance')
  prov.setAttribute('xmlns:me',NS)
  data = d.createElementNS(NS,'me:data')
  data.appendChild(d.createTextNode(env['data']))
  data.setAttribute('type','application/atom+xml')
  data.setAttribute('encoding',env['encoding'])
  prov.appendChild(data)
  alg = d.createElementNS(NS,'me:alg')
  alg.appendChild(d.createTextNode(env['alg']))
  prov.appendChild(alg)
  sig = d.createElementNS(NS,'me:sig')
  sig.appendChild(d.createTextNode(env['sig']))
  prov.appendChild(sig)
  d.documentElement.appendChild(prov)

  # Turn it back into text for consumption: 
  #Note: toprettyxml screws w/whitespace,
  # use only for debugging really
  #text = d.toprettyxml(encoding='utf-8')
  text = d.toxml(encoding='utf-8')
  d.unlink()
  return text


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
    #headers = self.request.headers;
    #logging.info('Headers =\n%s\n',headers)

    # TODO: Do a check for application/atom+xml and charset
    #content_type = headers['Content-Type'];
    #body = self.request.body.decode('utf-8')
    
    data = dict()
    self.response.out.write(template.render('magicsigdemo.html', data))
    self.response.set_status(200)

  @aclRequired
  def post(self):
    """Handles posting back of data and returns a result via XHR."""
    # TODO: Verify that current user session matches author of content, or throw error.
    data = self.request.get('data')
    format = self.request.get('format') or 'magic-envelope'
    logging.info('data = %s\n',data)
    env = createMagicEnv(data)
    assert(verifyMagicEnv(env))
    #logging.info('Created env = %s\n',env)
    logging.info("Created env! data:\n%s\nand signature:\n%s\n",env['data'],env['sig'])

    self.response.set_status(200) # The default
    if format == 'magic-envelope':
      self.response.out.write("""<?xml version='1.0' encoding='UTF-8'?>
<me:env xmlns:me='http://salmon-protocol.org/ns/magic-env'>
  <me:data type='application/atom+xml' encoding='"""+env['encoding']+"""'>\n"""+
    env['data']+"""</me:data>
  <me:alg>"""+env['alg']+"""</me:alg>
  <me:sig>"""+env['sig']+"""</me:sig>
</me:env>\n
"""
      )
    elif format == 'atom':
      #self.response.out.write("Content-Type: application/atom+xml; charset=utf-8\n\n")
      self.response.out.write(unfoldMagicEnv(env))
    else:
      self.response.set_status(400)
      raise "Unsupported format: "+format

class VerifyThisHandler(webapp.RequestHandler):
  """Handles request to verify a magic envelope or signed Atom entry.
  
  """
  def post(self):
    """  Intended to be called via XHR from magicsigdemo.html. """

    data = self.request.get('data')
    logging.info('data = %s\n',data)
    env = parseMagicEnv(data)
    logging.info('env = %s\n',env)

    self.response.set_status(200) # The default
    if verifyMagicEnv(env):
      self.response.out.write("OK")
      logging.info("Salmon signature verified!")
    else:
      self.response.out.write("Error: Signature does not validate.")
      logging.info("Salmon signature verification FAILED")

if __name__ == '__main__':
  main()
