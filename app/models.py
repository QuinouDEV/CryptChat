from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from config import Config
import uuid
import string
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

    private_key = db.Column(db.LargeBinary, nullable=True)
    public_key = db.Column(db.LargeBinary, nullable=True)

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.private_key = pem_private
        self.public_key = pem_public

    def get_private_key(self):
        return serialization.load_pem_private_key(self.private_key, password=None)

    def get_public_key(self):
        return serialization.load_pem_public_key(self.public_key)

class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    shared_key = db.Column(db.String(256), nullable=False)
    key_generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    user1 = db.relationship("User", foreign_keys=[user1_id])
    user2 = db.relationship("User", foreign_keys=[user2_id])

class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)  # message chiffré 
    plain_text = db.Column(db.Text, nullable=True)  # message en clair 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])

