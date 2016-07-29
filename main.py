import os
import re
import jinja2
import webapp2
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True) # prevent injection, hecking


def render_str(template, **params):
    # load file to create a ginja template
    t = jinja_env.get_template(template)
    return t.render(params)

_username_pattern = "^[a-zA-Z0-9_-]{3,20}$"
_password_pattern = "^.{3,20}$"
# email varification is simplified version, not to be used for production
_email_pattern = "^[\S]+@[\S]+.[\S]+$"

USER_RE = re.compile(_username_pattern)
def valid_username(username):
    return username and USER_RE.match(username)

def username_exist(username):
    existUser = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
    return existUser.count() != 0

def login_varify(username, password):
    existUser = db.GqlQuery("SELECT * FROM User WHERE username = :username AND password =:password", username = username, password = password)
    if existUser.count() != 0:
        return True
    else:
        return False

PASS_RE = re.compile(_password_pattern)
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(_email_pattern)
def valid_email(email):
    return email or EMAIL_RE.match(email)

def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# allow multipel user post for database organize purpose
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = True)

class Post(db.Model):
    username = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        # replace all new line char with line break html to render correctly
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # load file to create a ginja template
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Signup(Handler):
    def get(self):
        username = self.request.cookies.get('username')
        if valid_username(username):
            self.redirect('/welcome')
        else:
            self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username, email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if username_exist(username):
            params['error_username'] = "User name used. Please choose another user name"
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That's not a valid password."
            have_error = True

        elif password != verify:
            params['error_verify'] = "Your password didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup.html", **params)
        else:
            #self.response.headers['Content-Type'] = 'text/plain'
            newUser = User(username=username, password=password, email=email)
            newUser.put()
            username_cookie_val = make_secure_val(str(username))
            self.response.headers.add_header('Set-Cookie', 'username=%s'%username_cookie_val)
            self.redirect('/welcome')

def get_user_name(cookie):
    if cookie:
        if check_secure_val(cookie):
            return cookie.split('|')[0]
    return None

class Welcome(Handler):
    def get(self):
        username_cookie = self.request.cookies.get('username')
        username = get_user_name(username_cookie)
        if username:
            posts = db.GqlQuery("select * from Post where username = :username order by created desc limit 10", username = username)
            self.render('front.html', posts = posts, username = username)
        else:
            self.response.delete_cookie('username')
            self.redirect('/signup')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if login_varify(username, password):
            username_cookie_val = make_secure_val(str(username))
            self.response.headers.add_header('Set-Cookie', 'username=%s'%username_cookie_val)
            self.redirect('/welcome')
        else:
            self.render('login.html', error_password = 'password not correct')

class Logout(Handler):
    def get(self):
        self.response.delete_cookie('username')
        self.redirect('/welcome')

class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        username_cookie = self.request.cookies.get('username')
        username = get_user_name(username_cookie)
        if not username:
            error = 'Need to use cookie to login'
            self.render('newpost.html', subject=subject, content=content, error=error)
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                p = Post(parent=blog_key(), username=username, subject=subject, content=content)
                p.put() # store new object into database
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = 'subject and content, please!'
                self.render('newpost.html', subject=subject, content=content, error=error)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post = post)

app = webapp2.WSGIApplication([('/', Signup),
                               ('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage)], debug=True)
