markdown
# CryptChat

Bienvenue sur **CryptChat**, une application de messagerie sécurisée intégrant plusieurs méthodes de chiffrement pour garantir la confidentialité des échanges.

Ce projet utilise plusieurs systèmes de cryptographie :
- **AES**
- **RSA**
- **Vigenère**
- **César**

L'application est développée en **Python** avec le framework **Flask**. La persistance des données repose sur une base **MySQL** (XAMPP recommandé sous Windows).

---

## Fonctionnalités

- Système de chat en temps réel
- Chiffrement des messages via différents algorithmes
- Gestion des identités utilisateurs
- ReCAPTCHA pour sécuriser l'authentification
- Stockage sécurisé des informations dans une base de données MySQL

---

## Prérequis

Avant de lancer le projet, assure-toi d'avoir installé les dépendances suivantes :

- [Python 3](https://www.python.org/downloads/)
- [Flask](https://flask.palletsprojects.com/)
- [MySQL](https://www.mysql.com/) (ou [XAMPP](https://www.apachefriends.org/index.html) si tu es sous Windows)
- [pip](https://pip.pypa.io/en/stable/installation/)

---

## Fichier `.env`

Crée un fichier `.env` à la racine du projet avec la configuration suivante :

```ini
SECRET_KEY=XXXXXXXXXXXXXXXXXXXX
DB_HOST=localhost
DB_USER=XXXXXXXX
DB_PASSWORD=XXXXXXXX
DB_NAME=cryptchat
DATABASE_URL=mysql+pymysql://XXXXXXXX:XXXXXXXX@localhost:3306/cryptchat
RECAPTCHA_PUBLIC_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
RECAPTCHA_PRIVATE_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SESSION_LIFETIME=30
```

---

## Installation

1. Clone le dépôt :
   ```bash
   git clone https://github.com/TonPseudo/CryptChat.git
   cd CryptChat
   ```

2. Installe les dépendances Python :
   ```bash
   pip install -r requirements.txt
   ```

3. Assure-toi que MySQL est lancé (via XAMPP par exemple).

4. Exécute le serveur Flask :
   ```bash
   python run.py
   ```

---

## Technologies utilisées

- **Backend** : [Flask](https://flask.palletsprojects.com/)
- **Cryptographie** : AES, RSA, Vigenère, César
- **Base de données** : [MySQL](https://www.mysql.com/) (via XAMPP sur Windows)
- **ReCAPTCHA** : Google ReCAPTCHA v2

---

## Bon chat crypté ! 🔐
