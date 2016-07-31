import os
import re
import jinja2
import webapp2
import hashlib
import random
import string
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True) # prevent injection, hecking

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt):
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

def render_str(template, **params):
    # load file to create a ginja template
    t = jinja_env.get_template(template)
    return t.render(params)

# These patterns are from Udacity course
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
    existUser = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)

    if existUser.count():
        if valid_pw(username, password, existUser.get().password):
            return True
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
    like = db.StringListProperty(required = True)

class Post(db.Model):
    username = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now_add = True)
    like = db.StringListProperty(required = True)

    def render(self):
        # replace all new line char with line break html to render correctly
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

# This handler function is from udacity course video
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # load file to create a ginja template
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def cur_username(self):
        username_cookie = self.request.cookies.get('username')
        if username_cookie:
            if check_secure_val(username_cookie):
                return username_cookie.split('|')[0]
        else:
            return None

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
            hashed_credential = make_pw_hash(username, password, make_salt())
            newUser = User(username=username, password=hashed_credential, email=email, like=[])
            newUser.put()
            username_cookie_val = make_secure_val(str(username))
            self.response.headers.add_header('Set-Cookie', 'username=%s'%username_cookie_val)
            self.redirect('/welcome')



class Welcome(Handler):
    def get(self):
        username = self.cur_username()
        if username:
            posts = db.GqlQuery("select * from Post order by created desc limit 10")
            self.render('front.html', posts = posts, username = username)
        else:
            self.response.delete_cookie('username')
            self.redirect('/signup')

    def post(self):
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        #self.redirect('/blog/' + post_id)
        if not post:
            self.error(404)
            return

        username = self.cur_username()
        user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
        user = user_query.get()
        if username in post.like:
            # reclick will unliked
            post.like.remove(username)
            post.put()
            user.like.remove(post_id)
            user.put()
        # an author cannot like his own post
        elif post.username != username:
            post.like.append(username)
            post.put()
            user.like.append(post_id)
            user.put()
        # wait for database update
        time.sleep(0.5)
        self.redirect('/welcome')


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
        username = self.cur_username()
        self.render('newpost.html', username = username)

    def post(self):
        username = self.cur_username()
        if not username:
            self.render('login.html')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                p = Post(parent=blog_key(), username=username, subject=subject, content=content, like=[])
                p.put() # store new object into database
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = 'subject and content cannot be empty!'
                self.render('newpost.html', subject=subject, content=content, error=error)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        is_author = False
        username = self.cur_username()
        if post.username == username:
            is_author = True
        self.render('permalink.html', post = post, is_author = is_author, username = username)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        is_author = False
        username = self.cur_username()
        message = ''
        # an author cannot like his own post
        if post.username == username:
            is_author = True
            message = 'This is your post.'
        else:
            user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
            user = user_query.get()
            # an user cannot like a post more than once.
            if username in post.like:
                post.like.remove(username)
                post.put()
                message = 'unliked'
                user.like.remove(post_id)
                user.put()
            else:
                post.like.append(username)
                post.put()
                message = "like +1"
                user.like.append(post_id)
                user.put()
        self.render('permalink.html', post = post, username = username, is_author = is_author, message = message)

class DeletePost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            username = self.cur_username()
            if post.username == username:
                post.delete()
        # wait for database update
        time.sleep(0.5)
        self.redirect('/welcome')

class EditPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        username = self.cur_username()
        if post.username == username:
            self.render('editpost.html', subject=post.subject, content=post.content)
        else:
            self.redirect('/welcome')

    def post(self, post_id):
        username = self.cur_username()
        if not username:
            self.render('login.html')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/' + post_id)
            else:
                error = 'subject and content cannot be empty!'
                self.render('newpost.html', subject=subject, content=content, error=error)

class LikedPost(Handler):
    def get(self, username):
        username = self.cur_username()
        user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
        user = user_query.get()
        like_id_list = user.like
        posts = []
        for id in like_id_list:
            key = db.Key.from_path('Post', int(id), parent=blog_key())
            post = db.get(key)
            posts.append(post)
        self.render('likedpost.html', username = username, posts = posts)

app = webapp2.WSGIApplication([('/', Signup),
                               ('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/editpost/([0-9]+)', EditPost),
                               ('/blog/([0-9]+)', PostPage),
                               ('/liked/(.*)', LikedPost),
                               ('/deletepost/([0-9]+)', DeletePost)], debug=True)
