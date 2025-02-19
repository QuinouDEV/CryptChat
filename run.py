import pymysql
from app import create_app
from flask_migrate import upgrade
from config import Config
from flask import session, redirect, url_for
from datetime import timedelta
from flask_login import current_user

db_name = Config.DB_NAME

def initialize_database():
    print(f"[INFO] Vérification de l'existence de la base de données '{db_name}'...")
    try:
        with pymysql.connect(
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute(f"SHOW DATABASES LIKE '{db_name}'")
                if not cursor.fetchone():
                    print(f"[INFO] Création de la base de données '{db_name}'...")
                    cursor.execute(f"CREATE DATABASE {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
                    print(f"[INFO] Base de données créée avec succès !")
    except Exception as e:
        print(f"[ERREUR] Impossible de vérifier/créer la base de données : {e}")

initialize_database()

app = create_app()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Expire la session après 15 minutes d'inactivité

with app.app_context():
    import os
    if not os.path.exists("migrations"):  
        print("[INFO] Initialisation des migrations...")
        from flask_migrate import init, migrate
        init()
        migrate(message="Initial migration")
    
    print("[INFO] Application des migrations...")
    upgrade()

@app.before_request
def session_timeout():
    session.permanent = True  # Active le délai d'expiration de la session
    session.modified = True

if __name__ == "__main__":
    app.run(debug=True)
