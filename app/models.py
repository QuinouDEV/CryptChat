from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from config import Config
import uuid
import string

SECRET_KEY = Config.ENCRYPTION_KEY.encode()


def caesar_encrypt(plain_text, shift=3):
    alphabet = string.ascii_lowercase
    encrypted_text = []

    for char in plain_text:
        if char.isalpha():
            is_upper = char.isupper()
            new_char = alphabet[(alphabet.index(char.lower()) + shift) % 26]
            encrypted_text.append(new_char.upper() if is_upper else new_char)
        else:
            encrypted_text.append(char)

    return ''.join(encrypted_text)

def caesar_decrypt(cipher_text, shift=3):
    return caesar_encrypt(cipher_text, -shift)


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.Text, nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)


class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    shared_key = db.Column(db.String(256), nullable=False)
    key_generated_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp clé


    user1 = db.relationship("User", foreign_keys=[user1_id])
    user2 = db.relationship("User", foreign_keys=[user2_id])


class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])

    def encrypt_content(self, shift=3):
        self.content = caesar_encrypt(self.content, shift)

    def decrypt_content(self, shift=3):
        return caesar_decrypt(self.content, shift)
