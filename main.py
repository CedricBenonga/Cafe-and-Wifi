from functools import wraps
import sqlalchemy
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5

# # if Bootstrap5 gives red, please run these two lines of code to the terminal:
# pip uninstall flask-bootstrap bootstrap-flask
# pip install bootstrap-flask
# # And, in the interpreter under settings, uninstall both then install bootstrap-flask

from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# Connecting to DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Creating avatar profile images for user's comments
gravatar = Gravatar(
    app, size=100,
    rating='g',
    default='identicon',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


# Creating café Table
class CafePost(db.Model):
    __tablename__ = "cafe"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    map_url = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    has_sockets = db.Column(db.String(250), nullable=False)
    has_toilet = db.Column(db.String(250), nullable=False)
    has_wifi = db.Column(db.String(250), nullable=False)
    can_take_calls = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    coffee_price = db.Column(db.String(250), nullable=False)
    # Creating a relational database
    comments = relationship("Comment", back_populates="parent_post")


with app.app_context():
    db.create_all()


# Creating users Table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # Relational database
    comments = relationship("Comment", back_populates="comment_author")


with app.app_context():
    db.create_all()


# Creating comments Table
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # *******Add child relationship*******#
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # "users.id" The users refers to the tablename of the Users class.
    comment_author = relationship("User", back_populates="comments")
    # "comments" refers to the comments property in the User class.
    post_id = db.Column(db.Integer, db.ForeignKey("cafe.id"))
    parent_post = relationship("CafePost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


# Creating "registered only" decorator, restriction for none-registered users.
def registered_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user did not log in, forbid the access
        if not current_user.is_authenticated:
            return render_template("forbidden.html")
        # Else continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = CafePost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit() and request.method == "POST":

        # Checking if the user already exists
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("It looks like you're already one of us, please login instead!")  # to see this message,
            # you need to add some lines of code in the login.htl right on top of the form (in the same div).
            return redirect(url_for('login'))

        # Hashing and salting (encrypting) the password
        hashed_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )

        # Adding new user
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hashed_and_salted_password
        )

        # Saving the new user in the database
        db.session.add(new_user)
        db.session.commit()
        # Login and authenticate user after adding details to database.
        login_user(new_user)

        return redirect(url_for("get_all_posts", name=new_user.name))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit() and request.method == "POST":

        # Get data entered by the user
        email = request.form.get('email')  # or form.email.data
        password = request.form.get('password')  # or form.password.data

        # Find user in the DB by using the email entered.
        user = User.query.filter_by(email=email).first()

        # If email doesn't exist
        if not user:
            flash("This email does not exist, please try again.")
            return redirect(url_for('login'))

        # If password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))

        # If email exists in the DB and password correct, authorize access.
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = CafePost.query.get(post_id)
    form = CommentForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            return render_template("forbidden.html")

        new_comment = Comment(
            text=form.body.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    form.body.data = ""
    comments = Comment.query.all()
    return render_template("post.html", post=requested_post, form=form, current_user=current_user,
                           all_comments=comments)


@app.route("/new-post", methods=['GET', 'POST'])
@registered_only  # This decorator checks if the user is registered or not
def add_new_post():
    try:  # this checks if the user is duplicating a post or nor
        form = CreatePostForm()
        if form.validate_on_submit():
            new_post = CafePost(
                name=form.name.data,
                map_url=form.map_url.data,
                img_url=form.img_url.data,
                location=form.location.data,
                has_sockets=form.has_sockets.data,
                has_toilet=form.has_toilet.data,
                has_wifi=form.has_wifi.data,
                can_take_calls=form.can_take_calls.data,
                seats=form.seats.data,
                coffee_price=form.coffee_price.data,
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    except sqlalchemy.exc.IntegrityError:
        return render_template("duplicate.html")
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@registered_only  # This decorator checks if the user is registered or not
def edit_post(post_id):
    post = CafePost.query.get(post_id)
    edit_form = CreatePostForm(
        name=post.name,
        map_url=post.map_url,
        img_url=post.img_url,
        location=post.location,
        has_sockets=post.has_sockets,
        has_toilet=post.has_toilet,
        has_wifi=post.has_wifi,
        can_take_calls=post.can_take_calls,
        seats=post.seats,
        coffee_price=post.coffee_price
    )
    if edit_form.validate_on_submit():
        post.name = edit_form.name.data
        post.map_url = edit_form.map_url.data
        post.img_url = edit_form.img_url.data
        post.location = edit_form.location.data
        post.has_sockets = edit_form.has_sockets.data
        post.has_toilet = edit_form.has_toilet.data
        post.has_wifi = edit_form.has_wifi.data
        post.can_take_calls = edit_form.can_take_calls.data
        post.seats = edit_form.seats.data
        post.coffee_price = edit_form.coffee_price.data

        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete-comment/<int:comment_id>")
def delete_comment(comment_id):
    comment_to_delete = Comment.query.filter_by(id=comment_id).first()
    post_to_return = CafePost.query.filter_by(id=comment_to_delete.post_id).first()
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_to_return.id))


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = CafePost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return render_template("success.html", post=post_to_delete)


@app.route("/confirmation/<int:post_id>")
def confirm_delete(post_id):
    post_to_delete = CafePost.query.get(post_id)
    return render_template("confirm_delete.html", post=post_to_delete)


@app.route("/search", methods=["POST", "GET"])
def search():
    if request.method == 'POST':
        searched_cafe = request.form["search"]  # Or searched_cafe = request.args.get('search')
        all_cafes = CafePost.query.all()
        list_searched_cafe = []
        for cafe in all_cafes:
            if searched_cafe.lower() in cafe.name.lower() or searched_cafe.lower() in cafe.location.lower():
                list_searched_cafe.append(cafe)
        return render_template("index.html", all_posts=list_searched_cafe)


if __name__ == "__main__":
    app.run(debug=True)
