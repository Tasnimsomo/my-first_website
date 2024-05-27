#!/usr/bin/python3
from flask import Flask, render_template, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
import os
from models import Customer  # Import your Customer model
from database import session  # Import your database session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure SQLAlchemy database URI using environment variable
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return session.query(Customer).get(int(user_id))

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

    @staticmethod
    def from_customer(customer):
        return User(id=customer.id, username=customer.username, email=customer.email)

# Define the registration form
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = session.query(Customer).filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

    def validate_email(self, email):
        existing_user_email = session.query(Customer).filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email address is already registered.')

# Define the login form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    submit = SubmitField('Login')

# Routes

@app.route('/sereneglow')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_customer = Customer(username=form.username.data, email=form.email.data, password=hashed_password)
        session.add(new_customer)
        session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        customer = session.query(Customer).filter_by(email=form.email.data).first()
        if customer and bcrypt.check_password_hash(customer.password, form.password.data):
            user = User.from_customer(customer)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    # Get current user
    current_user = session.query(Customer).get(current_user.id)
    
    # Get product and quantity from form submission
    quantity = int(request.form['quantity'])
    product = session.query(Product).get(product_id)
    
    # Check if the product is already in the cart
    cart_item = session.query(CartItem).filter_by(product_id=product_id).first()
    
    if cart_item:
        # Update quantity if the product is already in the cart
        cart_item.quantity += quantity
    else:
        # Add new item to the cart
        cart_item = CartItem(product_id=product_id, quantity=quantity)
        current_user.shopping_cart.cart_items.append(cart_item)
    
    # Commit changes to the database
    session.commit()
    
    flash('Product added to cart successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
def remove_from_cart(cart_item_id):
    # Get current user
    current_user = session.query(Customer).get(current_user.id)
    
    # Get the cart item to remove
    cart_item = session.query(CartItem).get(cart_item_id)
    
    # Remove the cart item from the user's cart
    current_user.shopping_cart.cart_items.remove(cart_item)
    
    # Commit changes to the database
    session.commit()
    
    flash('Product removed from cart successfully!', 'success')
    return redirect(url_for('profile'))
if __name__ == '__main__':
    app.run(debug=True)

