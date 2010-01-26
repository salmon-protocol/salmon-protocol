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


# Just for bootstrapping, use test keypair:

the_test_keypair = "RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q=="

the_test_publickey = "RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB"

def createMagicEnv(text, userid):
  """Creates a magic envelope based on input text & current user.
     
  Note the importance of using the url-safe variant of base64
  encoding; without this, round trips through the Web are likely
  to result in subtle and hard to diagnose problems.  Specifically,
  this is standard base64 with - (dash) instead of + and _ (underscore)
  instead of '/'.
  """

  assert checkAuthorship(text, userid)

  # TODO: Get the private cert based on verifiable chain of evidence
  signer = signatures.SignatureAlgRsaSha1(the_test_keypair)
  B = base64.urlsafe_b64encode(unicode(text).encode("utf-8")).encode("utf-8")

  return dict(
    data = B,
    encoding = "base64",
    sig = signer.Sign(B),
    alg = signer.GetName(),
  )

def normalizeUserIdToUri(userid):
  """Normalizes a user-provided user id to a reasonable guess at a URI."""

  userid = strip(userid)

  # If already in a URI form, we're done:
  if userid.startswith("http:") or userid.startswith("https:") or userid.startswith("acct:"):
    return userid

  if userid.find("@") > 0:
    return "acct:"+userid

  # Catchall:  Guess at http: if nothing else works.
  return "http://"+userid
  

def checkAuthorship(text, userid):
  """Checks that userid is identified as an author of the content."""

  userid = normalizeUserIdToUri(userid)

  d = parseString(text)
  if d.documentElement.tagName == "entry":
    authors = d.documentElement.getElementsByTagName("author")
    for a in authors:
      uris = a.getElementsByTagName("uri")
      for uri in uris:
        logging.info("Saw author uri: %s\n", uri.firstChild.data)
        if uri.firstChild.data == userid:
          return True

  return False

def verifyMagicEnv(env):
  """Verifies a magic envelope (checks that its signature matches the
     contents)."""

  assert env['alg'] == "RSA-SHA1"
  assert env['encoding'] == "base64"
  verifier = signatures.SignatureAlgRsaSha1(the_test_publickey)

  logging.info("Verifying data:\n%s\n versus signature:\n%s\n",env['data'],env['sig'])

  return verifier.Verify(env['data'],env['sig'])


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
  logging.info("In unfoldMagicEnv, env[data] = \n%s\n",env['data'])

  d = parseString(base64.urlsafe_b64decode(env['data'].encode("utf-8")))
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
    """Handles posting back of data and returns a result via XHR.
       Just for demo purposes.  Accepts either data (an XML document)
       or env (a magic envelope) and returns output of magic-envelope
       or atom depending on format parameter."""

    # TODO: Verify that current user session matches author of content, or throw error.
    data = self.request.get('data')
    envText = self.request.get('env')
    format = self.request.get('format') or 'magic-envelope'
    if data:  
      logging.info('posted Atom data = %s\n',data)
      userid = users.get_current_user().email();

      # Do an ACL check to see if current user is properly identified as an author:
      if not checkAuthorship(data, userid):
        logging.info("Authorship check failed for user %s\n",userid)
        self.response.set_status(400)
        self.response.out.write("User "+userid+" not an author of entry, cannot sign.")
        return

      # Sign the content on behalf of user:
      env = createMagicEnv(data,userid)
    elif envText:
      logging.info('posted Magic envelope env = %s\n',envText)
      env = parseMagicEnv(envText)

    # Just to sanity check:
    assert verifyMagicEnv(env)

    #logging.info("Created env! data:\n%s\nand signature:\n%s\n",env['data'],env['sig'])

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
      self.response.set_status(400) # Input error (does not validate)
      self.response.out.write("Signature does not validate.")
      logging.info("Salmon signature verification FAILED")

if __name__ == '__main__':
  main()
