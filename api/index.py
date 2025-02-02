from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
import boto3
import random
import os
from dotenv import load_dotenv
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gizli_anahtar_buraya'  # Güvenli bir secret key kullanın
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kelime_ogrenme.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor.')
            return redirect(url_for('signup'))
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('home'))
    
    return render_template('../signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        
        flash('Geçersiz kullanıcı adı veya şifre.')
    
    return render_template('../login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('../day.html')

@app.route('/learn')
@login_required
def learn():
    return render_template('../learn.html')

@app.route('/story')
@login_required
def story():
    return render_template('../story.html')

@app.route('/summary')
@login_required
def summary():
    return render_template('../summary.html')

@app.route('/quiz')
@login_required
def quiz():
    return render_template('../quiz.html')

@app.route('/quiz_result', methods=['POST'])
@login_required
def quiz_result():
    return render_template('../quiz_result.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('../dashboard.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)