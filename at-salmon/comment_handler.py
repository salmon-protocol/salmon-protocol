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

import imports
import magicsig
import webfingerclient.webfinger as webfinger
import simplejson as json
import datamodel

# TODO: refactor this into datamodel or somewhere shared.
def extract_mentions(text):
  # http://stackoverflow.com/questions/201323/what-is-the-best-regular-expression-for-validating-email-addresses :)
  mentionsRegex = re.compile('@[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+')
  #mentionsRegex = re.compile('@[^\s]+') #@-anything followed by a space
  matches = mentionsRegex.findall(text)
  mentions = []
  for match in matches:
    match = match[1:len(match)] # remove leading @
    mentions.append(match)
  return list(set(mentions)) #set() to de-dupe

def do_salmon_slaps(mentions):
  client = webfinger.Client()
  for id in mentions:
    xrd_list = client.lookup(id)
    for item in xrd_list:
      logging.info("Got webfinger result for %s: %s" % (id, item))
      # item is a Xrd proto2, not a string, no need to decode.
      subject = item.subject
      slap_urls = key_urls = [link.href for link in item.links if link.rel
                              == 'http://salmon-protocol.org/ns/salmon-mention']
      logging.info('Salmon slaps: subject %s, %s' % (subject, slap_urls) )
      # TODO: actually post to the salmon-mention URLs.

class CommentHandler(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user()
    commentResults = db.GqlQuery("SELECT * FROM Comment WHERE parent_uri = :parent_uri", parent_uri=self.request.url)
    comments = []
    for comment in commentResults:
      comments.append(self.decorate_comment(comment))

    mentions = []
    user_email = ''
    if user:
      user_email = user.email()

    template_values = {
      'parent_uri': self.request.url,
      'comments': comments,
      'mentions': mentions,
      'user': user_email,
      'logout_url': users.create_logout_url('/'),
      'login_url' : users.create_login_url('/') }
    path = os.path.join(os.path.dirname(__file__), 'comments.html')
    self.response.out.write(template.render(path, template_values))

  def decorate_comment(self, comment):
    comment.decorated_content = comment.content
    client = webfinger.Client()
    for mention in comment.mentions:
      replacer = re.compile(mention)
      # relying on memcache to make this not painful.  Should probably store this with the original
      # mention information on write. (TODO)
      try:
        # use http://webfinger.net/rel/profile-page rel link from webfinger to get link to profile page.
        xrd_list = client.lookup(mention)
        profile_uris = ['about:blank']
        for item in xrd_list:
          profile_uris = [link.href for link in item.links if link.rel
                                  == 'http://webfinger.net/rel/profile-page']
        linkedMention = "<a href='%s' title='Link to profile for %s'>%s</a>" % (profile_uris[0], mention, mention)
        comment.decorated_content = replacer.sub(linkedMention, comment.decorated_content)
      except:
        pass #TODO: log?

    return comment
    
  def post(self):
    comment_text = self.request.get('comment-text')
    comment_mentions = extract_mentions(comment_text)
    comment_text = self.request.get('comment-text')
    client = webfinger.Client()
    profile_uris = ['about:blank']
    try:
      xrd_list = client.lookup(users.get_current_user().email())
      for item in xrd_list:
        profile_uris = [link.href for link in item.links if link.rel
                              == 'http://webfinger.net/rel/profile-page']
    except:
      pass #TODO: log?

    c = datamodel.Comment(
      author = users.get_current_user(), 
      author_profile = profile_uris[0],
      posted_at = datetime.datetime.now(),
      content = comment_text,
      mentions = comment_mentions,
      parent_uri = self.request.url)
    c.put()
    do_salmon_slaps(comment_mentions)

    self.response.out.write("thanks");
    self.redirect(self.request.url);

