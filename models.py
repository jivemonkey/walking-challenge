from google.appengine.ext import db
from webapp2_extras import auth
from hashlib import sha1
import webapp2
import hmac
import logging
import time

class User(db.Model):
	"""Universal user model. Can be used with App Engine's default users API,
	   own auth or third party authentication methods (OpenId, OAuth etc).
	"""
	password_salt = "Hb987*&d7dhS"
	
	# Creation date.
	created = db.DateTimeProperty(auto_now_add=True)
    
	# Modification date.
	updated = db.DateTimeProperty(auto_now=True)
    
	# User defined unique name, also used as key_name.
	first_name = db.StringProperty(required=True)
    
    # User defined unique name, also used as key_name.
	last_name = db.StringProperty(required=True)
    
	# Password, only set for own authentication.
	password = db.StringProperty(required=False)
    
	# User email
	email = db.StringProperty(required=False)
    
	# Admin flag.
	is_admin = db.BooleanProperty(default=False)

	def get_id(self):
		"""Returns this user's unique ID, which can be an integer or string."""
		return self.key()

	@classmethod
	def make_password_hash(self, password):
		return hmac.new(self.password_salt, 
						password, 
						sha1).hexdigest()

	@classmethod
	def create_user(cls, user):
		usercount = User.gql("WHERE email = :1", user.email).count()
		
		if usercount > 0:
			raise Exception('Email already registered')
		
		user.password = cls.make_password_hash(user.password)
		
		user.put()

	@classmethod
	def get_by_auth_token(cls, user_id, token):
		"""
		Returns a user object based on a user ID and token.
		:param user_id: The user_id of the requesting user.
        :param token: The token string to be verified.
        :returns: A tuple ``(User, timestamp)``, with a user object and
		the token timestamp, or ``(None, None)`` if both were not found.
		"""
		if cls.make_password_hash(str(user_id)) != token:
			return (None, None)
		
		user = cls.get(user_id)
		
		if not user:
			return (None, None)

		return (user, int(time.time()))

	@classmethod
	def get_by_auth_password(cls, auth_id, password):
		"""
		Returns a user object, validating password.
		:param auth_id: Authentication id.
		:param password: Password to be checked.
		:returns: A user object, if found and password matches.
		:raises: ``auth.InvalidAuthIdError`` or ``auth.InvalidPasswordError``.
		"""
		password = cls.make_password_hash(password)
		
		logging.debug('password: %s'%password)
		
		user = cls.gql("WHERE email = :1 and password = :2", auth_id, password).get()
        
		if not user:
			raise auth.InvalidAuthIdError()
        	
		return user

	@classmethod
	def create_auth_token(cls, user_id):
		"""
		Creates a new authorization token for a given user ID.
		:param user_id: User unique ID.
		:returns: A string with the authorization token.
		"""
		return cls.make_password_hash(str(user_id))

	@classmethod
	def delete_auth_token(cls, user_id, token):
		"""
		Deletes a given authorization token.
		:param user_id: User unique ID.
		:param token: A string with the authorization token.
		"""

class Activity(db.Model):
	created = db.DateTimeProperty(auto_now_add=True)
	count = db.IntegerProperty(required=True)
	type = db.StringProperty(required=True)
	comment = db.StringProperty()
	
class Compitition(db.Model):
	start = db.DateTimeProperty(required=True)
	end = db.DateTimeProperty(required=True)
	name = db.StringProperty(required=True)
	
class Comment(db.Model):
	created = db.DateTimeProperty(auto_now_add=True)
	text = db.StringProperty(required=True)
	user_id = db.ReferenceProperty()
	parent_comment = db.SelfReferenceProperty()