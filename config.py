import os
from datetime import timedelta
from cryptography.fernet import Fernet

KEY_FILE = "secret.key" 

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else: 
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'change_this_secret_key')  # 🔹 METTRE SA CLÉ SECRÈTE ICI (Utilisée pour les sessions et la protection CSRF)
    
    # 🔹 CONFIGURATION BASE DE DONNÉES MYSQL
    DB_HOST = os.getenv('DB_HOST', 'localhost')  # Adresse du serveur MySQL (ex: localhost, 127.0.0.1, ou une IP distante)
    DB_USER = os.getenv('DB_USER', 'root')  # Nom d'utilisateur MySQL
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')  # Mot de passe de la base de données (laisser vide si aucun mot de passe n'est défini)
    DB_NAME = os.getenv('DB_NAME', 'cryptchat')  # Nom de la base de données utilisée par l'application
    
    # 🔹 CONFIGURATION GOOGLE reCAPTCHA
    # Obtenez vos clés API ici : https://www.google.com/recaptcha/admin
    RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY', '')  # Clé publique (site key) pour intégrer reCAPTCHA
    RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY', '')  # Clé privée (secret key) pour valider le reCAPTCHA côté serveur

    # 🔹 CHIFFREMENT DES DONNÉES
    ENCRYPTION_KEY = load_or_create_key().decode()  # Clé de chiffrement utilisée pour sécuriser certaines données sensibles
    
    # 🔹 LIMITATION DES TENTATIVES DE CONNEXION
    MAX_LOGIN_ATTEMPTS = 3  # Nombre maximal de tentatives de connexion avant de bloquer temporairement l'utilisateur
    LOGIN_TIMEOUT = 300  # Durée de blocage après dépassement du nombre de tentatives (en secondes, ici 5 minutes)
    
    # 🔹 DURÉE DE SESSION
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv('SESSION_LIFETIME', 30)))  # Durée de vie de la session (30 minutes par défaut)

    # 🔹 CONNEXION À LA BASE DE DONNÉES
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"  # Chaîne de connexion SQLAlchemy
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Désactiver le suivi des modifications pour économiser les ressources
