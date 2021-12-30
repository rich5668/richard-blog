from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Establishing relationship between tables

Base = declarative_base()

# Initialize Gravatar for comment profile pictures
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES
# User Table (Parent for Comment and BlogPost)
class User(UserMixin, db.Model, Base):
    # What table is called in database file
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    is_admin = db.Column(db.Boolean)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.

    # Between User and BlogPost Class
    posts = relationship("BlogPost", back_populates="author")

    # Between User and Comment Class
    comments = relationship("Comment", back_populates="comment_author")


# Blog Table (Child to User and Parent to Comment)
class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Child Relationship
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    # ***************Parent Relationship*************#
    # Between Blogpost and Comment Class
    comments = relationship("Comment", back_populates="parent_post")


# Comments Table(Child to User and BlogPost)
class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    # Between User and Comment Class
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # Between Blogpost and Comment Class
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# Create Database Tables
# db.create_all()

# Login Manager
# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


# admin decorator

def admin_only(function):
    # @wrap(function) Copies all docstring information for inserted function such as __name__ and __doc__ and
    # inserts function docstring information into wrapper function so the original function docstring
    # information is not lost.
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        users_id = current_user.get_id()
        user = User.query.get(users_id)
        if not current_user.is_authenticated or not user.is_admin:
            print("I'm aborting")
            return abort(403)

        return function(*args, **kwargs)

    return wrapper_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    user = None
    posts = BlogPost.query.all()

    if current_user.is_authenticated:
        user_id = current_user.get_id()
        user = load_user(user_id=user_id)

    # current_user is a variable already defined by flask-login which gives you the information of current user
    return render_template("index.html", all_posts=posts, user=user)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()

    if register_form.validate_on_submit() and request.method == "POST":
        new_email = request.form["email"]
        new_password = request.form["password"]
        new_name = request.form["name"]

        user = User.query.filter_by(email=new_email).first()

        if user != None:
            flash("You've already signed up, please login!")
            return redirect(url_for("login"))

        hashed_and_salted_password = generate_password_hash(
            password=new_password,
            method='pbkdf2:sha256',
            salt_length=8,
        )

        new_user = User(
            email=new_email,
            password=hashed_and_salted_password,
            name=new_name,
            is_admin=False,
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()

    if request.method == "POST" and login_form.validate_on_submit():

        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(pwhash=user.password, password=password):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        elif not user:
            flash("The email does not exist, please try again.")
            return redirect(url_for("login"))
        elif not check_password_hash(pwhash=user.password, password=password):
            flash("Incorrect password, please try again.")
            return redirect(url_for("login"))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    # Finding current user visiting page
    users_id = current_user.get_id()
    user = User.query.get(users_id)

    requested_post = BlogPost.query.get(post_id)

    comment_form = CommentForm()

    post_comments = Comment.query.filter_by(post_id=post_id)

    if request.method == "POST":

        if not current_user.is_authenticated:
            flash("Please login to post a comment.")
            return redirect(url_for("login"))

        if comment_form.validate_on_submit():
            comment_text = request.form["comment_text"]

            new_comment = Comment(
                text=comment_text,
                comment_author=current_user,
                parent_post=requested_post,
            )

            print("post")
            db.session.add(new_comment)
            db.session.commit()

            return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html", post=requested_post, user=user, form=comment_form, post_comments=post_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author=current_user,

        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", methods=["GET", "POST"])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# Turns a regular user into an admin (For testing purposes)
@app.route("/make-admin")
def make_admin():
    users_id = current_user.get_id()
    user = User.query.get(users_id)

    user.is_admin = True
    db.session.commit()

    return f"{user.name} was made an admin."


# Turns an admin into a regular user (For testing purposes)
@app.route("/make-regular")
def make_regular():
    users_id = current_user.get_id()
    user = User.query.get(users_id)

    user.is_admin = False
    db.session.commit()

    return f"{user.name} is no longer an admin."


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
