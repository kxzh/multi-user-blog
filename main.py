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

_like_message = "like +1"
_unlike_message = 'unliked'
_like_own_message = 'This is your post.'
_no_permission_message = 'Sorry. You are not the author of this post.'
_login_message = 'Please login.'
_comment_success_message = 'Comment posted'
_deleted_message = 'Deleted'
_error_message = 'error'

# These patterns are from Udacity course
_username_pattern = "^[a-zA-Z0-9_-]{3,20}$"
_password_pattern = "^.{3,20}$"
# email varification is simplified version, not to be used for production
_email_pattern = "^[\S]+@[\S]+.[\S]+$"


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


USER_RE = re.compile(_username_pattern)
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(_password_pattern)
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(_email_pattern)
def valid_email(email):
    return email or EMAIL_RE.match(email)


def username_exist(username):
    if username:
        user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
        user = user_query.get()
        if user:
            return True
    return False

def login_varify(username, password):
    existUser = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
    if existUser.count():
        if valid_pw(username, password, existUser.get().password):
            return True
    return False


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
    post = db.StringListProperty(default=[])

class Post(db.Model):
    username = db.StringProperty(required = True)
    subject = db.StringProperty(default='')
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True, auto_now=False)
    last_modified = db.DateTimeProperty(auto_now = True)
    like = db.StringListProperty(default=[])
    comment = db.ListProperty(db.Key)

    def render(self):
        # replace all new line char with line break html to render correctly
        self._render_text = self.content.replace('\n', '<br>')
        comment_block = ''
        # For now, only support rendering maximum of 10 comments (earliest)
        # TODO: Rendering more comments
        i = 0
        for comment_key in self.comment:
            if i > 9:
                break
            comment_holder = db.get(comment_key)
            if comment_holder:
                comment_block += comment_holder.render()
                i += 1
        return render_str('post.html', p = self, comment_block = comment_block)

class Comment(Post):
    parent_post_id = db.StringProperty(required = True)
    def render(self):
        # replace all new line char with line break html to render correctly
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('comment.html', p = self)

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
    # Varify user identity with both local cookie and server database
    def isLogin(self):
        username = self.cur_username()
        if username:
            user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
            user = user_query.get()
            if user:
                return True
        return False

class Signup(Handler):
    def get(self):
        self.response.delete_cookie('username')
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(email = email)

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
            # wait for database update
            time.sleep(0.5)
            self.redirect('/welcome')

class Welcome(Handler):
    def get(self, message=''):
        username = self.cur_username()
        posts = db.GqlQuery("SELECT * FROM Post order by created desc limit 10")
        if self.isLogin():
            self.render('front.html', posts = posts, username = username, message = message)
        else:
            self.render('front.html', posts = posts, message = message)

    def post(self, message=''):
        # Visitor not signed in cannot like/comment/edit/delete a post/comment
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/' + message)
            return
        # when user like/unlike a post on the front page,
        # a post_id hidden fild is auto filled with the id of that post
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        username = self.cur_username()
        user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
        user = user_query.get()
        # log in user can like a post
        if username in post.like:
            # reclick will unliked
            post.like.remove(username)
            post.put()
            user.like.remove(post_id)
            user.put()
            message = _unlike_message
        elif post.username != username:
            post.like.append(username)
            post.put()
            user.like.append(post_id)
            user.put()
            message = _like_message
        # an author cannot like his own post
        elif post.username == username:
            message = _like_own_message

        # wait for database update
        time.sleep(0.5)
        self.redirect('/welcome/' + message)

class Login(Handler):
    def get(self):
        self.response.delete_cookie('username')
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
        if self.isLogin():
            self.render('editpost.html', username = username, post_type='New Post')
        else:
            message = _login_message
            self.redirect('/welcome/' + message)
            return

    def post(self):
        if not self.isLogin():
            self.redirect('/login')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            username = self.cur_username()
            if subject and content:
                user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
                user = user_query.get()
                p = Post(parent=blog_key(), username=username, subject=subject, content=content, like=[])
                p.put()
                post_id = p.key().id()
                user.post.append(str(post_id))
                user.put()
                self.redirect('/blog/%s' % str(post_id))
            else:
                error = 'subject and content cannot be empty!'
                self.render('editpost.html', post_type = 'New Post', subject=subject, content=content, error=error, username = username)

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
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/' + message)
            return

        like_button = self.request.get('like_button')
        comment_button = self.request.get('comment_button')
        username = self.cur_username()
        is_author = False

        if comment_button:
            comment = self.request.get('comment')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            # an author cannot like his own post
            if post.username == username:
                is_author = True
            p = Comment(parent=key, username=username, content=comment, parent_post_id=post_id)
            p.put()
            post.comment.append(p.key())
            post.put()
            message = _comment_success_message
            self.render('permalink.html', post = post, username = username, is_author = is_author, message = message)

        elif like_button:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            # an author cannot like his own post
            if post.username == username:
                is_author = True
                message = _like_own_message
            else:
                user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
                user = user_query.get()
                # an user cannot like a post more than once.
                if username in post.like:
                    post.like.remove(username)
                    post.put()
                    message = _unlike_message
                    user.like.remove(post_id)
                    user.put()
                else:
                    post.like.append(username)
                    post.put()
                    message = _like_message
                    user.like.append(post_id)
                    user.put()
            self.render('permalink.html', post = post, username = username, is_author = is_author, message = message)

class DeleteBlog(Handler):
    def get(self, post_id):
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/'+message)
            return

        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        blog = db.get(post_key)
        username = self.cur_username()

        if not blog:
            message = 'Blog does not exist'
            self.redirect('/welcome/'+message)
        elif blog.username != username:
            message = _no_permission_message
            self.redirect('/welcome/'+message)
        else:
            # delete all comments entries of this blog
            for comment_key in blog.comment:
                comment = db.get(comment_key)
                if comment:
                    comment.delete()
            blog.delete()
            time.sleep(0.5) # wait for database update
            message = _deleted_message
            self.redirect('/welcome/'+message)

class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/'+message)
            return
        else:
            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            blog = db.get(post_key)
            comment_key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
            comment = db.get(comment_key)
            if comment and blog:
                username = self.cur_username()
                if comment.username == username:
                    blog.comment.remove(comment_key)
                    comment.delete()
                    blog.put()
                    # wait for database update
                    time.sleep(0.5)
                    self.redirect('/blog/'+post_id)
                else:
                    message = _no_permission_message
                    self.redirect('/welcome/'+message)
            else:
                self.redirect('/blog/'+post_id)

class EditPost(Handler):
    def get(self, post_id):
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/'+message)
            return
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            username = self.cur_username()
            if post.username == username:
                self.render('editpost.html', post_type="Edit Post", subject=post.subject, content=post.content, username=username, post_id=post_id)
            else:
                message = _no_permission_message
                self.redirect('/welcome/'+message)

    def post(self, post_id):
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/'+message)
            return
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            username = self.cur_username()
            if not subject or not content:
                error = 'subject and content cannot be empty!'
                self.render('editpost.html', post_type = 'Edit Post', subject=subject, content=content, error=error, username=username)
                return
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if post.username == username:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/' + post_id)
            else:
                message = _no_permission_message
                self.redirect('/welcome/'+message)

class LikedPost(Handler):
    def get(self, username):
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/'+message)
            return
        else:
            username = self.cur_username()
            user_query = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username)
            user = user_query.get()
            if username and user:
                like_id_list = user.like
                posts = []
                for id in like_id_list:
                    key = db.Key.from_path('Post', int(id), parent=blog_key())
                    post = db.get(key)
                    if post:
                        posts.append(post)
                self.render('likedpost.html', username = username, posts = posts)
            else:
                message = _login_message
                self.redirect('/welcome/'+message)

class EditComment(Handler):
    def get(self, post_id, comment_id):
        if not self.isLogin():
            self.redirect('/login')
            # message = _login_message
            # self.redirect('/welcome/'+message)
            return
        else:
            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            blog = db.get(post_key)
            comment_key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
            comment = db.get(comment_key)
            username = self.cur_username()
            if not comment:
                message = _error_message
                self.redirect('/welcome/'+message)
            elif comment.username == username:
                self.render('editcomment.html', comment = comment.content, username = username)
            else:
                message = _no_permission_message
                self.redirect('/welcome/'+message)

    def post(self, post_id, comment_id):
        new_comment = self.request.get('comment')
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        blog = db.get(post_key)
        comment_key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
        comment = db.get(comment_key)
        if blog and comment:
            if comment.username == self.cur_username():
                comment.content = new_comment
                comment.put()
                self.redirect('/blog/'+post_id)
            else:
                message = _no_permission_message
                self.redirect('/welcome/'+message)
        else:
            message = _error_message
            self.redirect('/welcome/'+message)



app = webapp2.WSGIApplication([('/', Welcome),
                               ('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/welcome/(.*)', Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/editpost/([0-9]+)', EditPost),
                               ('/blog/([0-9]+)', PostPage),
                               ('/liked/(.*)', LikedPost),
                               ('/deletecomment/([0-9]+)/([0-9]+)', DeleteComment),
                               ('/deletepost/([0-9]+)', DeleteBlog),
                               ('/editcomment/([0-9]+)/([0-9]+)', EditComment)], debug=True)
