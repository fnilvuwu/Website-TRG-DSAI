from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    current_user,
    logout_user,
)
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

# Debugging prints
print("FLASK_KEY:", os.environ.get("FLASK_KEY"))
print("POSTGRES_URL_NON_POOLING:", os.environ.get("POSTGRES_URL_NON_POOLING"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("POSTGRES_URL_NON_POOLING")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(
    app,
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)


# CONFIGURE TABLES


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")


# Create the User Table


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    comments = relationship("Comment", back_populates="comment_author")
    posts = relationship("BlogPost", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    text = db.Column(db.Text, nullable=False)

    comment_author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return function(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/")
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

@app.route("/tes-index")
def tes_index():
    return render_template("tes-index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=form.email.data).first():
            hash_and_salted_password = generate_password_hash(
                form.password.data, method="pbkdf2:sha256", salt_length=8
            )
            new_user = User(
                email=form.email.data,
                name=form.name.data,
                password=hash_and_salted_password,
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            return redirect(url_for("get_all_posts"))
        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        requested_user = User.query.filter_by(email=form.email.data).first()
        if not requested_user:
            flash("The email does not exist, please try again.")
            return redirect(url_for("login"))

        elif not check_password_hash(requested_user.password, form.password.data):
            flash("Password incorrect, please try again.")
            return redirect(url_for("login"))

        else:
            login_user(requested_user)

            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")

            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.body.data, comment_author=current_user, parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/our-team")
def our_team():
    return render_template("our-team.html")

@app.route("/publication")
def publication():
    return render_template("publication.html")

@app.route("/research-projects")
def research_projects():
    return render_template("research-projects.html")

@app.route("/activities")
def activities():
    return render_template("activities.html")

@app.route('/research-group-overview')
def research_group_overview():
    return render_template('research-group-overview.html') 

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/api/hello")
def api():
    return render_template("api/hello.js")

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
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route(
    "/edit-post/<int:post_id>",
)
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
        date=date.today().strftime("%B %d, %Y"),
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        post.date = edit_form.date
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
