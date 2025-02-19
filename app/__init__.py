from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect


db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()  
socketio = SocketIO(cors_allowed_origins="*")  # WebSocket activé



def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app) 



    from app.routes.auth import auth_bp
    from app.routes.main import main_bp 
    from app.routes.chat import chat_bp 


    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(chat_bp)


    login_manager.login_view = "auth.login"
    login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."

    with app.app_context():
        from app import models 

    @login_manager.user_loader
    def load_user(user_id):
        return models.User.query.get(int(user_id))
                           
    return app

