#!/usr/bin/env python
#
# Copyright 2008 Google Inc.
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

"""Simple subscriber that aggregates all feeds together and demonstrates Salmon."""

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
import model
from model import Entry
from signatures import *


""" Helpers """
def aclRequired(func):
  def wrapper(self, *args, **kw):
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url(self.request.uri))
    else:
      if not (users.is_current_user_admin() or userdb.is_registered_user(user)):
        self.response.out.write("Sorry "+user.email()+", you are not on my allowed list.  Talk to John if you want to be added.")
        self.response.out.write("<br><a href=\""+users.create_logout_url(self.request.uri)+"\">logout</a>");
        self.response.set_status(403)
      else:
        func(self, *args, **kw)
  return wrapper


class SalmonizeHandler(webapp.RequestHandler):
  """Handles request to salmonize an external feed.

  This is just for testing, in order to get real feed data
  from live feed sources.  However a feed proxy like
  Feedburner could offer Salmon-as-a-service as well.
  """
  
  def get(self):
    feedurl = self.request.get('feed')
    data = feedparser.parse(feedurl)
    
    # Augment with a salmon endpoint. TODO: Don't overwrite existing!
    endpoint = u'http://'+self.request.headers['Host']+'/post'
    data.feed.links.append({'href' : endpoint,'type': u'application/atom+xml', 'rel': u'salmon'})
    # if feedfields.bozo:
    # TODO: Annotate stored data and/or hand back a warning.

    # TODO: Have an alternate template that just shows the Atom with the salmon stuff highlighted in some way.
    self.response.out.write(template.render('atom.xml', data))
    self.response.set_status(200)
    
    # And store the entries discovered in our own DB for reference.
    for entry in data.entries:
      e = model.makeEntry(entry,data.feed)
      #logging.info('Made %s from %s',e,entry)
      db.put([e])
      logging.info('Remembering entry with title = "%s", id = "%s", '
                   'link = "%s"', 
                   e.title, e.entry_id, e.link)

class InputHandler(webapp.RequestHandler):
  """Handles newly posted salmon"""

  def post(self):
    headers = self.request.headers;
    logging.info('Headers =\n%s\n',headers)
    in_reply_to = self.request.get('inreplyto') #Get this from entry thr:in-reply-to if possible; feedparser.py BUG here

    # TODO: Do a check for application/atom+xml and charset
    content_type = headers['Content-Type'];
    body = self.request.body.decode('utf-8')

    logging.info('Post body is %d characters', len(body))
    logging.info('Post body is:\n%s\n----', body);

    data = feedparser.parse(body)
    logging.info('Data returned was:\n%s\n----',data)
    if data.bozo:
      logging.error('Bozo feed data. %s: %r',
                     data.bozo_exception.__class__.__name__,
                     data.bozo_exception)
      if (hasattr(data.bozo_exception, 'getLineNumber') and
          hasattr(data.bozo_exception, 'getMessage')):
        line = data.bozo_exception.getLineNumber()
        logging.error('Line %d: %s', line, data.bozo_exception.getMessage())
        # segment = self.request.body.split('\n')[line-1]
        # logging.info('Body segment with error: %r', segment.decode('utf-8'))
      return self.response.set_status(500)

    update_list = []
    logging.info('Found %d entries', len(data.entries))
    for entry in data.entries:
      s = model.makeEntry(entry)
 
      referents = model.getTopicsOf(s)
      
      logging.info('Saw %d parents!', referents.count() )
      if referents.count() == 0:
        logging.info('No parent found for %s, returning error to client.',s.entry_id)
        self.response.set_status(400)
        self.response.out.write('Bad Salmon, no parent with id '+unicode(s.in_reply_to)+' found -- rejected.\n');
        return

      # Look for parents, update thread_updated if necessary 
      for parent in referents:
        logging.info('Saw parent: %s\n',parent)
        if parent.thread_updated < s.updated:
          parent.thread_updated = s.updated 
          parent.put()

      update_list.append(s)

    db.put(update_list)
    self.response.set_status(200)
    self.response.out.write("Salmon accepted, swimming upstream!\n");

class RiverHandler(webapp.RequestHandler):
  """Displays a very simple river of Salmon aggregator."""
  
  @aclRequired
  def get(self):
    N = 500
    context = dict(entries=model.getLatestPosts(N))
    if context['entries']:
      for entry in context['entries']:
        #logging.info("Entry = %s",dumper.dump(entry))
        replies = model.getRepliesTo(entry,N)
        if replies:
          entry.replies = replies
    self.response.out.write(template.render('ros.html', context))

class ReplyHandler(webapp.RequestHandler):
  """Provides a semi-helpful reply mechanism."""

  @login_required
  def get(self):
    context = dict()
    context['parent'] = model.getEntryById(self.request.get('inreplyto'))
    context['newid'] = "tag:example.com,2009:cmt-%.8f" % random.random();
    u = users.get_current_user();
    context['user'] = dict(nickname=u.nickname(), email=u.email())
    context['signature'] = genSignature(context['newid'],context['parent'].entry_id,'','acct'+u.email())
    context['timestamp'] = datetime.datetime.utcnow().isoformat()
    self.response.out.write(template.render('reply.html', context))

class LatestHandler(webapp.RequestHandler):
  """Shows latest entries, salmon or otherwise, seen in a straight list """

  @aclRequired
  def get(self):
    stuff=[]
    for salmon in Entry.gql('ORDER BY updated DESC').fetch(10):
      text = cgi.escape(salmon.content if salmon.content else '(no content)')
      text = text[0:30]
      if len(text) > 29:
        text = text + "..."
      stuff.append({'updated': str(salmon.updated),
                    'content': text,
                    'link': salmon.link,
                    'author_name': salmon.author_name,
                    'author_uri': salmon.author_uri,
                    'in_reply_to': salmon.in_reply_to})
    self.response.out.write(template.render('latest.html',dict(salmon=stuff))) 

class MainHandler(webapp.RequestHandler):
  """Main page of the server."""
  
  @aclRequired
  def get(self):
    context = dict(logouturl=users.create_logout_url(self.request.uri))
    self.response.out.write(template.render('index.html',context))

  
      
application = webapp.WSGIApplication(
  [
    (r'/salmonize', SalmonizeHandler),
    (r'/post', InputHandler),
    (r'/latest', LatestHandler),
    (r'/ros', RiverHandler),
    (r'/reply.do', ReplyHandler),
    (r'/', MainHandler),
  ],
  debug=True)


def main():
  wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
  main()
