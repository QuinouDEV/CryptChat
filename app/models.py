from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from config import Config
import uuid
import string

SECRET_KEY = Config.ENCRYPTION_KEY.encode()

def vigenere_encrypt(plain_text, key):
    alphabet = string.ascii_lowercase
    key = key.lower()
    encrypted_text = []

    key_index = 0
    for char in plain_text:
        if char.isalpha():
            shift = alphabet.index(key[key_index % len(key)])
            if char.islower():
                encrypted_text.append(alphabet[(alphabet.index(char) + shift) % 26])
            elif char.isupper():
                encrypted_text.append(alphabet[(alphabet.index(char.lower()) + shift) % 26].upper())
            key_index += 1
        else:
            encrypted_text.append(char)

    return ''.join(encrypted_text)

def vigenere_decrypt(cipher_text, key):
    alphabet = string.ascii_lowercase
    key = key.lower()
    decrypted_text = []

    key_index = 0
    for char in cipher_text:
        if char.isalpha():
            shift = alphabet.index(key[key_index % len(key)])
            if char.islower():
                decrypted_text.append(alphabet[(alphabet.index(char) - shift) % 26])
            elif char.isupper():
                decrypted_text.append(alphabet[(alphabet.index(char.lower()) - shift) % 26].upper())
            key_index += 1
        else:
            decrypted_text.append(char)

    return ''.join(decrypted_text)

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


class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])

    def encrypt_content(self, key):
        self.content = vigenere_encrypt(self.content, key)

    def decrypt_content(self, key):
        return vigenere_decrypt(self.content, key)
