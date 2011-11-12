#!/usr/bin/env python
import webapp2
import jinja2
import os
import models
from webapp2_extras import auth
from webapp2_extras import sessions
from google.appengine.ext import db
import logging
from datetime import datetime,timedelta
from pytz.gae import pytz

jenv = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__) + "/views/"))

def require_login(handler):
	"""
		Decorator for checking if there's a user associated with the current session.
		Will also fail if there's no session present.
	"""
	def check_login(self, *args, **kwargs):
		auth = self.auth
		if not auth.get_user_by_session():
			# If handler has no login_url specified invoke a 403 error
			try:
				self.redirect(('/login?redirect=%s'%self.request.environ['PATH_INFO']))
			except (AttributeError, KeyError), e:
				self.abort(403)
		else:
			return handler(self, *args, **kwargs)

	return check_login

# Base handler that sets up session
class BaseHandler(webapp2.RequestHandler): 
	def dispatch(self):
		# Get a session store for this request.
		self.session_store = sessions.get_store(request=self.request)
		
		try:
			# Dispatch the request. 
			webapp2.RequestHandler.dispatch(self)
		finally:
			# Save all sessions. 
			self.session_store.save_sessions(self.response)
	
	@webapp2.cached_property
	def session(self):
		# Returns a session using the default cookie key. 
		return self.session_store.get_session()

	@webapp2.cached_property
	def auth(self):
		return auth.get_auth()

	@webapp2.cached_property
	def session_store(self):
		return sessions.get_store(request=self.request)
		
	def respond(self, template,*args, **kwargs):
		user_vars = self.auth.get_user_by_session()
		
		if user_vars:
			kwargs['login_name'] = user_vars['first_name']

		kwargs['_url'] = self.request.environ['PATH_INFO']
			
		template = jenv.get_template(template)
		self.response.out.write(template.render(*args,**kwargs))

# Handle index
class MainPage(BaseHandler):
	def get(self):
		self.respond('index.html')

# Handle login
class Login(BaseHandler):
	def get(self):
		"""
			Returns a simple HTML form for login
		"""
		self.respond('login.html', redirect = self.request.GET.get('redirect'))

	def post(self):
		"""
			username: Get the username from POST dict
			password: Get the password from POST dict
		"""
		email = self.request.POST.get('email')
		password = self.request.POST.get('password')
		redirect = self.request.POST.get('redirect')
		
		# Try to login user with password
		# Raises InvalidAuthIdError if user is not found
		# Raises InvalidPasswordError if provided password doesn't match with specified user
		try:
			user = self.auth.get_user_by_password(email, password)
			self.redirect(redirect);
		except (auth.InvalidAuthIdError, auth.InvalidPasswordError), e:
			# Returns error message to self.response.write in the BaseHandler.dispatcher
			# Currently no message is attached to the exceptions
			self.redirect('/login?error=%s'%'BadLogin');

class CreateUser(BaseHandler):
	def get(self):
		self.respond("new_user.html")
	def post(self):
		"""
		Get the info from POST dict
		"""
		email = self.request.POST.get('email')
		first_name = self.request.POST.get('first_name')
		last_name = self.request.POST.get('last_name')
		password = self.request.POST.get('password')

		try:
			user = models.User(email = email, 
							first_name=first_name,
							last_name=last_name,
							password=password)
			
			models.User.create_user(user)
			self.redirect('/login')
		except(Exception), e:
			self.get()

class EditUser(BaseHandler):
	@require_login
	def get(self):
		user_vars = self.auth.get_user_by_session()
		user = models.User.get(user_vars['user_id'])
		
		user_form = { 'email': user.email, 'first_name': user.first_name, 'last_name': user.last_name, 'key': user.key() }

		self.respond("user.html", user_form)

	@require_login
	def post(self):
		"""
		Get the info from POST dict
		"""
		email = self.request.POST.get('email')
		first_name = self.request.POST.get('first_name')
		last_name = self.request.POST.get('last_name')
		key = self.request.POST.get('key')
		
		user = models.User.get(key)
		
		if not user:
			self.get()
			return
		
		try:
			user.email = email
			user.first_name = first_name
			user.last_name = last_name
			user.put()
			self.redirect('/')
		except(Exception), e:
			self.response.out.write(e)

class ChangePassword(BaseHandler):
	@require_login
	def get(self):
		self.respond('password.html')

	@require_login
	def post(self):
		current_password = self.request.POST.get('current_password')
		new_password = self.request.POST.get('new_password')
		confirm_password = self.request.POST.get('confirm_password')
		user_vars = self.auth.get_user_by_session()
		
		user = models.User.get(user_vars['user_id'])
		
		if not user:
			self.get()
			return
		
		if user.password != models.User.make_password_hash(current_password):
			self.response.out.write("Old password doesn't match")
			return
		elif new_password != confirm_password:
			self.response.out.write("New password does not match confirmation.")
			return
		
		try:
			user.password = models.User.make_password_hash(new_password)
			user.put()
			self.redirect('/')
		except(Exception), e:
			self.response.out.write(e)

class Logout(BaseHandler):
	"""
		Destroy user session and redirect to login
	"""
	def get(self):
		self.auth.unset_session()
		# User is logged out, let's try redirecting to login page
		try:
			self.redirect('/')
		except (AttributeError, KeyError), e:
			return "User is logged out"

class Activity(BaseHandler):
	@require_login
	def get(self):
		self.respond('activity.html')

	@require_login
	def post(self):
		user_vars = self.auth.get_user_by_session()
		created = self.request.POST.get('created')
		count = self.request.POST.get('count')
		comment = self.request.POST.get('comment')
		
		try:
			activity = models.Activity(key_name="%s:%s"%(user_vars['user_id'],created),
									count=int(count), 
									created=datetime.strptime(created,'%m/%d/%Y'), 
									type="walking", 
									comment=comment,
									parent=user_vars['user_id'])
			activity.put()
			self.redirect('/dashboard')
		except Exception, e:
			self.response.out.write(e)

class UserDashBoard(BaseHandler):
	@require_login
	def get(self):
		user_vars = self.auth.get_user_by_session()
		activities = models.Activity.gql('WHERE ANCESTOR IS :1 order by created', user_vars['user_id'])
		tz = pytz.timezone('US/Pacific')
		now = datetime.now(tz)
		dow = now.weekday()
		
		now = datetime(now.year,now.month,now.day)

		start = now - timedelta(days=28+dow)
		end = now + timedelta(days=(6-dow))

		cal = {}
		week_total= [0,0,0,0,0,]
		week_count=0
		day = 0
		for activity in activities:
			cal[activity.created] = activity
			
		while start <= end:
			if start not in cal:
				cal[start] = None;
			else:
				week_total[week_count] += cal[start].count
			start = start + timedelta(days=1)
			if ((day+1) % 7) == 0:
				week_count += 1
			day += 1
		
		self.respond('user_dashboard.html', cal=sorted(cal.iteritems()), today=now, week_total=week_total)

class CompititionDashboard(BaseHandler):
	def get(self):
		self.respond('compitition_dashboard.html')

class CommentCreate(BaseHandler):
	def post(self):
		user_vars = self.auth.get_user_by_session()
		activity_id = self.request.POST.get('activity_id')
		text = self.request.POST.get('text')
		
		comment = models.Comment(parent=account_id, text=text, user_id=user_vars['user_id'])
		
		try:
			comment.put()
		except Exception, e:
			self.reponse.out.write(e)

# List of compitition winners
class LeaderBoard(BaseHandler):
	def get(self):
		self.response.out.write("Leader Board")

class ReqLook(BaseHandler):
	def get(self):
		for key, value in self.request.environ.iteritems():
			self.response.out.write("%s=%s<br>"%(key,value))

config = {}
config['webapp2_extras.sessions'] = {'secret_key': 'my-super-secret-key', 
						'cookie_name': 'wtwc'}
						
config['webapp2_extras.auth'] = {'user_model': 'models.User', 
								 'cookie_name': 'wtwc',
								 'session_backend':'memcache',
								 'user_attributes':['email','first_name','is_admin',]}

logging.getLogger().setLevel(logging.DEBUG)
app = webapp2.WSGIApplication([('/', MainPage),
							('/login', Login),
							('/user', EditUser), 
							('/leaders', LeaderBoard),
							('/register', CreateUser),
							('/password', ChangePassword),
							('/logout', Logout),
							('/activity', Activity),
							('/dashboard',UserDashBoard),
							('/comment', CommentCreate),
							('/compitition', CompititionDashboard),
							('/req', ReqLook)],
							config = config,
                            debug=True)

def main():
    app.run()

if __name__ == '__main__':
    main()