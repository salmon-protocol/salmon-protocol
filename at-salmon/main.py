#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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

import os
import datetime
import re
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
from google.appengine.api import users
from google.appengine.ext import db
from google.appengine.ext.webapp import logging

import xml.etree.ElementTree as et
import imports
import magicsig
import webfingerclient.webfinger as webfinger
import simplejson as json
import datamodel
import comment_handler
import profile_handler
import mentions_handler

class MainHandler(webapp.RequestHandler):

  def get(self):
    self.redirect('/comment');

class SalmonSlapHandler(webapp.RequestHandler):
  def post(self):
    # Retrieve putative Salmon from input body.
    body = self.request.body
    mime_type = self.request.headers['Content-Type']

    logging.info("Saw body:\n%s\n" % body)
    envelope = magicsig.Envelope(
        document=body,
        mime_type=mime_type)
    # If we got here, the Salmon validated.

    # Grab out the fields of interest:
    entry = envelope.GetParsedData().getroot()

    s = et.tostring(entry,encoding='utf-8')
    logging.info('Saw entry:\n%s\n' % s)

    ns = '{http://www.w3.org/2005/Atom}'
    ans = '{http://activitystrea.ms/spec/1.0/}'
    author=entry.findtext(ns+'author/'+ns+'uri')
    posted_at_str=entry.findtext(ns+'updated')
    content=entry.findtext(ns+'content')
    if not content:
      content=entry.findtext(ans+'object/'+ns+'content')
    if not content:
      content=entry.findtext(ns+'summary')
    if not content:
      content=entry.findtext(ns+'title')
    if not content:
      content=''
    content=content.strip()
    logging.info('Content = %s' % content)

    author = users.User(re.sub('^acct:','',author))

    mentions = comment_handler.extract_mentions(content)

    logging.info('About to add: author=%s, content=%s, mentions=%s' % (author,
                                                                       content,
                                                                       mentions))

    c = datamodel.Comment(
        author=author,
        posted_at=datetime.datetime.now(),  #should convert posted_at_str,
        content=content,
        mentions=mentions)
    c.put()
    self.response.set_status(202)
    self.response.out.write("Salmon accepted!\n")

# Following handlers implement a ghetto version of lrdd.
# Should package this up and make it more real and make
# it easy to drop into a webapp.

class GhettoHostMeta(webapp.RequestHandler):
  path = os.path.join(os.path.dirname(__file__), 'host-meta.xml')

  def get(self):
    host = self.request.headers['Host']
    vals = dict(hostauthority='http://%s' % host,
                host=re.sub(':[0-9]+','',host))
    self.response.out.write(template.render(self.path,
                                            vals))
    self.response.set_status(200)

class GhettoUserXRD(webapp.RequestHandler):
  path = os.path.join(os.path.dirname(__file__), 'user-xrd.xml')

  def get(self):
    user_uri = self.request.get('q')
    host = self.request.headers['Host']

    # The following will recurse once we implement Webfinger outbound lookup,
    # which will be a good reminder to replace it with Nigori or similar:
    key = magicsig.KeyRetriever().LookupPublicKey(user_uri)
    keyuri = 'data:application/magic-public-key;%s' % key

    vals = dict(subject=user_uri, keyuri=keyuri, host=host)
    self.response.out.write(template.render(self.path,
                                            vals))

# End of ghetto lrdd

def main():
  application = webapp.WSGIApplication(
      [
          ('/', MainHandler),
          ('/mentions.*', mentions_handler.MentionsHandler),
          ('/comment.*', comment_handler.CommentHandler),
          ('/profile.*', profile_handler.ProfileHandler),
          ('/salmon-slap', SalmonSlapHandler),
          ('/.well-known/host-meta', GhettoHostMeta),
          ('/user', GhettoUserXRD),
      ],
      debug=True)
  util.run_wsgi_app(application)


if __name__ == '__main__':
  main()
