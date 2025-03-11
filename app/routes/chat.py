from flask import Blueprint, render_template, request
from flask_socketio import emit, join_room
from flask_login import current_user, login_required
from app.models import User, ChatSession, Message
from datetime import datetime, timedelta
from app import socketio, db
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode

chat_bp = Blueprint("chat", __name__, url_prefix="/chat")


@chat_bp.route("/<string:receiver_id>")
@login_required
def chat(receiver_id):
    receiver = User.query.filter_by(uuid=receiver_id).first()
    if not receiver:
        return f"Receiver with ID {receiver_id} not found."

    messages = Message.query.filter(
        (Message.sender_id == current_user.id) & (Message.receiver_id == receiver.id) |
        (Message.sender_id == receiver.id) & (Message.receiver_id == current_user.id)
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    private_key = current_user.get_private_key()

    for msg in messages:

        if msg.sender_id == receiver.id:
            try:
                encrypted_data = b64decode(msg.content)
                decrypted_msg = private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
            except Exception as e:
                decrypted_msg = "Erreur de déchiffrement"
        else:

            decrypted_msg = msg.plain_text or "[Message envoyé]"

        decrypted_messages.append((msg.sender.username, decrypted_msg))

    return render_template("chat.html", receiver=receiver, messages=decrypted_messages)



@chat_bp.route("/get_public_key/<string:receiver_id>", methods=["GET"])
@login_required
def get_public_key(receiver_id):
    receiver = User.query.filter_by(uuid=receiver_id).first()
    if not receiver:
        return {"error": "Utilisateur introuvable"}, 404

    return {
        "public_key": receiver.public_key.decode()  # PEM
    }, 200

@socketio.on("join")
def on_join(data):
    user_id = data["user_id"]
    room = f"user_{user_id}"
    join_room(room)
    print(f"User {user_id} joined room {room}")
    
@socketio.on("message")
def handle_message(data):
    receiver_id = data.get("receiver_id")
    message_text = data.get("message")

    if not receiver_id or not message_text:
        return

    receiver = User.query.filter_by(id=receiver_id).first()
    if not receiver:
        print(f"Receiver {receiver_id} not found.")
        return

    # --- Chiffrement RSA --
    receiver_public_key = receiver.get_public_key()
    encrypted_message = receiver_public_key.encrypt(
        message_text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encoded_message = b64encode(encrypted_message).decode()

    sender_private_key = current_user.get_private_key()
    signature = sender_private_key.sign(
        message_text.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )

    encoded_signature = b64encode(signature).decode()

    message = Message(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        content=encoded_message,
        plain_text=message_text 
    )
    db.session.add(message)
    db.session.commit()

    emit("message", {
        "username": current_user.username,
        "sender_uuid": current_user.uuid,
        "message": message_text,
        "signature": encoded_signature
    }, room=f"user_{receiver.id}")

    emit("message", {
        "username": current_user.username,
        "sender_uuid": current_user.uuid,
        "message": message_text,
        "signature": encoded_signature
    }, room=f"user_{current_user.id}")

