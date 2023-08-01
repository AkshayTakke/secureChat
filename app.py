import os
from datetime import datetime

import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from flask_session import Session
from models import ChatMessage
from models import db, User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False

db.init_app(app)
Session(app)


def create_tables():
    db.create_all()


@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('home.html')
    else:
        return render_template('landing.html')
        # return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))

        private_key, public_key = generate_rsa_key_pair()

        private_key_str = private_key.decode()
        public_key_str = public_key.decode()

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, public_key=public_key_str,
                        private_key=private_key_str)
        db.session.add(new_user)
        db.session.commit()

        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


@app.route('/chat/<int:recipient_id>', methods=['GET'])
def view_messages(recipient_id):
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    recipient_user = User.query.get(recipient_id)

    if not recipient_user:
        flash('Invalid recipient', 'error')
        return redirect(url_for('chat'))

    if current_user.id == recipient_user.id:
        flash('You cannot chat with yourself', 'error')
        return redirect(url_for('chat'))

    received_messages = ChatMessage.query.filter(
        (ChatMessage.sender_id == recipient_id) &
        (ChatMessage.recipient_id == current_user.id)
    ).order_by(ChatMessage.timestamp).all()

    received_messages = ChatMessage.query.filter(
        (ChatMessage.sender_id == recipient_id) &
        (ChatMessage.recipient_id == current_user.id)
    ).order_by(ChatMessage.timestamp).all()

    recipient_private_key = serialization.load_pem_private_key(
        current_user.private_key.encode(),
        password=None,
        backend=default_backend()
    )

    decrypted_received_messages = []
    for message in received_messages:
        try:
            decrypted_message = recipient_private_key.decrypt(
                message.message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            decrypted_received_messages.append(decrypted_message)
        except Exception:
            decrypted_received_messages.append("[Decryption Error]")

    sent_messages = ChatMessage.query.filter(
        (ChatMessage.sender_id == current_user.id) &
        (ChatMessage.recipient_id == recipient_id)
    ).order_by(ChatMessage.timestamp).all()

    recipient_private_key = serialization.load_pem_private_key(
        recipient_user.private_key.encode(),
        password=None,
        backend=default_backend()
    )

    decrypted_sent_messages = []
    for message in sent_messages:
        try:
            decrypted_message = recipient_private_key.decrypt(
                message.message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            decrypted_sent_messages.append(decrypted_message)
        except Exception:
            decrypted_sent_messages.append("[Decryption Error]")

    return jsonify({
        'received_messages': decrypted_received_messages,
        'sent_messages': decrypted_sent_messages
    })


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])

    if request.method == 'POST':
        recipient_id = request.form['recipient']
        recipient_user = User.query.get(recipient_id)
        message = request.form['message']

        if not recipient_user.public_key:
            flash('Recipient does not have a valid public key', 'error')
            return jsonify({'status': 'failed'})

        recipient_public_key = serialization.load_pem_public_key(
            recipient_user.public_key.encode(),
            backend=default_backend()
        )

        try:
            ciphertext = recipient_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            flash('Encryption failed. Please try again later.', 'error')
            return jsonify({'status': 'failed'})

        # Save the encrypted message and other metadata to the database
        encrypted_message = ChatMessage(
            sender_id=current_user.id,
            recipient_id=recipient_user.id,
            message=ciphertext,
            timestamp=datetime.utcnow()
        )
        db.session.add(encrypted_message)
        db.session.commit()

        return jsonify({'status': 'success'})
    current_user = User.query.get(session['user_id'])
    users = User.query.filter(User.id != session['user_id']).all()
    return render_template('chat.html', current_user=current_user, users=users)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
