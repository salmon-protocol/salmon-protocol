from google.appengine.ext import db

class Comment(db.Expando):
  parent_uri = db.StringProperty(required=False)
  author = db.UserProperty(required=True)
  author_profile = db.TextProperty(required=False)
  author_id = db.TextProperty(required=False)
  author_nickname = db.TextProperty(required=False)
  posted_at = db.DateTimeProperty(required=True)
  content = db.TextProperty(required=True)
  mentions = db.StringListProperty()

class Profile(db.Expando):
  localname = db.StringProperty(required=True)
  host_authority = db.StringProperty(required=True)
  nickname = db.StringProperty()
  owner = db.UserProperty(required=True)
  public_key = db.UserProperty(required=False)
