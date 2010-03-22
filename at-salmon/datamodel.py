from google.appengine.ext import db

class Comment(db.Expando):
  parent_uri = db.StringProperty(required=False)
  author = db.UserProperty(required=True)
  author_profile = db.TextProperty(required=False)
  posted_at = db.DateTimeProperty(required=True)
  content = db.TextProperty(required=True)
  mentions = db.StringListProperty()
