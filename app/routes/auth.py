from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User
import uuid  
from app.forms import LoginForm, RegisterForm
from app import db

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Connexion réussie.", "success")
            return redirect(url_for("auth.user_list"))
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect.", "danger")
    return render_template("login.html", form=form)

@auth_bp.route("/users")
@login_required
def user_list():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template("user_list.html", users=users)

@auth_bp.route("/search", methods=["GET"])
@login_required
def search_user():
    query = request.args.get("q", "").strip()
    if query:
        user = User.query.filter(User.username.ilike(f"%{query}%")).first()
        if user:
            return redirect(url_for("chat.chat", receiver_id=user.uuid))
        else:
            flash("Utilisateur introuvable.", "danger")
    return redirect(url_for("auth.user_list"))

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Ce nom d'utilisateur est déjà pris.", "danger")
        elif form.password.data != form.confirm_password.data:
            flash("Les mots de passe ne correspondent pas.", "danger")
        else:
            new_user = User(
                username=form.username.data,
                uuid=str(uuid.uuid4())  # Génération et stockage d'un UUID unique
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash("Inscription réussie. Vous pouvez maintenant vous connecter.", "success")
            return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)




@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for("auth.login"))