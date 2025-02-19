from flask import Blueprint, render_template, request
from flask_socketio import emit
from flask_login import current_user, login_required
from app.models import User, Message
from app import socketio, db

chat_bp = Blueprint("chat", __name__, url_prefix="/chat")

@chat_bp.route("/<string:receiver_id>")
@login_required
def chat(receiver_id):
    receiver = User.query.filter_by(uuid=receiver_id).first()
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) & (Message.receiver_id == receiver.id) |
        (Message.sender_id == receiver.id) & (Message.receiver_id == current_user.id)
    ).order_by(Message.timestamp.asc()).all()
    return render_template("chat.html", receiver=receiver, messages=messages)

@socketio.on("message")
def handle_message(data):
    receiver_id = data.get("receiver_id")
    message_text = data.get("message")

    if receiver_id and message_text:
        message = Message(sender_id=current_user.id, receiver_id=receiver_id, content=message_text)
        db.session.add(message)
        db.session.commit()

        emit("message", {
            "username": current_user.username,
            "message": message_text
        }, broadcast=True)
