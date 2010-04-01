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

def query_mentions(user_uri):
  mentions = []
  mentionResults = db.GqlQuery("SELECT * FROM Comment where mentions = :user_uri",
                               user_uri=user_uri)
  for mention in mentionResults:
    mentions.append(decorate_comment(mention))

  return mentions

def decorate_comment(comment):
  comment.decorated_content = comment.content
  comment.author_uri = comment.author_id
  logging.info("Author_uri = %s" % comment.author_uri)
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


_PROFILE_RE = re.compile('/profile/([^/.]+)', re.VERBOSE)

def ensure_profile(user, host_authority):
  p = get_profile_for_user(user)
  if p:
    return p
  else:
    return create_profile_for_user(user, host_authority)

def get_profile_for_user(user):
  profileResults = db.GqlQuery("SELECT * FROM Profile WHERE owner = :owner",
                                 owner=user).fetch(1)
  if len(profileResults) == 0:
    return None
  else:
    return profileResults[0]

_ACCT_RE = re.compile('(acct:)?([^@]+)@(.+)', re.VERBOSE)

def get_profile_by_localname(localname):
  match = _ACCT_RE.match(localname)
  if match:
    localname = match.group(2)

  profileResults = db.GqlQuery("SELECT * FROM Profile WHERE localname = :localname",
                                localname=localname).fetch(1)
  if len(profileResults) == 0:
    return None
  else:
    return profileResults[0]

def create_profile_for_user(user, host_authority):
  localname_base = user.email().split('@')[0]
  localname = localname_base
  counter = 1
  while True:
    r = db.GqlQuery("SELECT * FROM Profile WHERE localname = :localname",
                    localname=localname).fetch(1)
    if len(r) == 0:
      break  # Does not exist
    
    counter += 1
    localname = localname_base + str(counter)
      
  # (Small race condition here we don't care about for a demo)
  # (Using a default public key here instead of generating one on the fly.  Should
  # probably use None instead until the user writes a comment and then generate one.)
  p = datamodel.Profile(
    localname = localname,
    host_authority = host_authority,
    owner = user,
    nickname = localname,
    publickey = 'RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
                'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww=='
                '.AQAB')
  p.put()

class ProfileHandler(webapp.RequestHandler):
  def get(self):
    logging.info("Saw a GET to /profile handler!")
    user = users.get_current_user()
    logging.info("Path = %s" % self.request.path)
    match = _PROFILE_RE.match(self.request.path)
    if not match:
      self.response.out.write('Badly formed profile URL!')
      self.response.set_status(400) 
      return

    # Grab localname; if it's the special @me metavariable,
    # substitute with the actual users's local profile name
    # (creating a default on the fly if needed.)
    localname = match.group(1)
    if localname == '%40me':
      profile = ensure_profile(user, self.request.host)
    else:
      profile = get_profile_by_localname(localname)

    if not profile:
      self.response.out.write("Profile not found!")
      self.response.set_status(404)
      return

    is_own_profile = False
    if user:
      is_own_profile = user.email == profile.owner.email

    fulluserid = profile.localname + '@' + profile.host_authority
    template_values = {
      'fulluserid': fulluserid,
      'is_own_profile': is_own_profile,
      'localname': profile.localname,
      'nickname': profile.nickname,
      'mentions': query_mentions(fulluserid),
      'user': profile.owner.email,
      'publickey': profile.publickey,
      'logout_url': users.create_logout_url(self.request.path),
      'login_url' : users.create_login_url(self.request.path) }
    path = os.path.join(os.path.dirname(__file__), 'profile.html')
    self.response.out.write(template.render(path, template_values))

  def post(self):
    user = users.get_current_user()
    newlocalname = self.request.get('newlocalname')
    oldlocalname = self.request.get('oldlocalname')
    newnickname = self.request.get('newnickname')
    newpublickey = self.request.get('newpublickey')
    profileResults = db.GqlQuery("SELECT * FROM Profile WHERE localname = :localname",
                                 localname=oldlocalname).fetch(1)
    if len(profileResults) == 0:
      # Doesn't exist, so create it:
      logging.info("Creating %s %s %s" % (newlocalname, user, newnickname) )
      p = datamodel.Profile(
        localname = newlocalname,
        host_authority = self.request.host,
        owner = user,
        nickname = newnickname,
        publickey = newpublickey)
    else:
      # Already exists, update if ACL checks out:
      logging.info("Updating %s with %s %s %s" % (oldlocalname, newlocalname,
                                                  user, newnickname) )
      p = profileResults[0]
      if p.owner == user:
        p.nickname = newnickname
        p.localname = newlocalname
        p.host_authority = self.request.host
        p.publickey = newpublickey
      else:
        self.response.set_status(403)  #Forbidden!
        return

    p.put()

    self.redirect('http://'+p.host_authority+'/profile/'+p.localname)
