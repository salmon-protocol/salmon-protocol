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
import mentions_handler

_PROFILE_RE = re.compile('/profile/([^/.]+)', re.VERBOSE)

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

    profileResults = db.GqlQuery("SELECT * FROM Profile WHERE localname = :localname",
                                 localname=match.group(1)).fetch(1)
    if len(profileResults) == 0:
      self.response.out.write("Not found!")
      self.response.set_status(404)
      return

    profile = profileResults[0]
    is_own_profile = False
    if user:
      is_own_profile = user.email == profile.owner.email

    fulluserid = profile.localname + '@' + self.request.host
    template_values = {
      'fulluserid': fulluserid,
      'is_own_profile': is_own_profile,
      'localname': profile.localname,
      'nickname': profile.nickname,
      'mentions': mentions_handler.query_mentions(fulluserid),
      'user': profile.owner.email,
      'logout_url': users.create_logout_url(self.request.path),
      'login_url' : users.create_login_url(self.request.path) }
    path = os.path.join(os.path.dirname(__file__), 'profile.html')
    self.response.out.write(template.render(path, template_values))

  def post(self):
    user = users.get_current_user()
    newlocalname = self.request.get('newlocalname')
    oldlocalname = self.request.get('oldlocalname')
    newnickname = self.request.get('newnickname')
    profileResults = db.GqlQuery("SELECT * FROM Profile WHERE localname = :localname",
                                 localname=oldlocalname).fetch(1)
    if len(profileResults) == 0:
      # Doesn't exist, so create it:
      logging.info("Creating %s %s %s" % (newlocalname, user, newnickname) )
      p = datamodel.Profile(
        localname = newlocalname,
        owner = user,
        nickname = newnickname)
    else:
      # Already exists, update if ACL checks out:
      logging.info("Updating %s with %s %s %s" % (oldlocalname, newlocalname,
                                                  user, newnickname) )
      p = profileResults[0]
      if p.owner == user:
        p.nickname = newnickname
        p.localname = newlocalname
      else:
        self.response.set_status(403)  #Forbidden!
        return

    p.put()

    self.redirect('http://'+self.request.host+'/profile/'+p.localname)
