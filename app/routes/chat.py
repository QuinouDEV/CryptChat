import secrets
from flask import Blueprint, render_template, request, jsonify
from flask_socketio import join_room, emit
import hashlib
from flask_login import current_user, login_required
from app.models import User, ChatSession, Message, aes_encrypt, aes_decrypt
from datetime import datetime, timedelta
from app import socketio, db

chat_bp = Blueprint("chat", __name__, url_prefix="/chat")

PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
BASE = 2

def generate_diffie_hellman_key():
    private_key = secrets.randbelow(PRIME)
    public_key = pow(BASE, private_key, PRIME)
    return private_key, public_key

def derive_aes_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode()
    aes_key = hashlib.sha256(shared_secret_bytes).digest()
    return aes_key.hex()

@chat_bp.route("/exchange_key/<string:receiver_id>", methods=["POST"])
@login_required
def exchange_key(receiver_id):
    receiver = User.query.filter_by(uuid=receiver_id).first()
    if not receiver:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    session = ChatSession.query.filter(
        ((ChatSession.user1_id == current_user.id) & (ChatSession.user2_id == receiver.id)) |
        ((ChatSession.user2_id == current_user.id) & (ChatSession.user1_id == receiver.id))
    ).first()

    if not session:
        private_key_sender, public_key_sender = generate_diffie_hellman_key()
        private_key_receiver, public_key_receiver = generate_diffie_hellman_key()
        shared_secret = pow(public_key_receiver, private_key_sender, PRIME)

        aes_key = derive_aes_key(shared_secret)

        session = ChatSession(
            user1_id=current_user.id,
            user2_id=receiver.id,
            shared_key=aes_key,
            key_generated_at=datetime.utcnow()
        )
        db.session.add(session)
        db.session.commit()

    return jsonify({"public_key": session.shared_key}), 200

@chat_bp.route("/<string:receiver_id>")
@login_required
def chat(receiver_id):
    receiver = User.query.filter_by(uuid=receiver_id).first()
    if not receiver:
        return f"Receiver with ID {receiver_id} not found."

    response = exchange_key(receiver_id)
    if response[1] != 200:
        return "Erreur lors de la génération de clé."

    session = ChatSession.query.filter(
        ((ChatSession.user1_id == current_user.id) & (ChatSession.user2_id == receiver.id)) |
        ((ChatSession.user2_id == current_user.id) & (ChatSession.user1_id == receiver.id))
    ).first()

    if not session:
        return "Aucune session trouvée pour cet utilisateur."

    shared_key_hex = session.shared_key

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver.id)) |
        ((Message.sender_id == receiver.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for msg in messages:
        try:
            decrypted_msg = aes_decrypt(msg.content, shared_key_hex)
            decrypted_messages.append((msg.sender.username, decrypted_msg))
        except Exception as e:
            decrypted_messages.append((msg.sender.username, "[Message corrompu]"))

    return render_template("chat.html", receiver=receiver, messages=decrypted_messages)

@socketio.on("connect")
def handle_connect():
    if current_user.is_authenticated:
        join_room(str(current_user.id))

@socketio.on("message")
def handle_message(data):
    receiver_id = data.get("receiver_id")
    encrypted_message = data.get("message")

    if not receiver_id or not encrypted_message:
        return

    session = ChatSession.query.filter(
        ((ChatSession.user1_id == current_user.id) & (ChatSession.user2_id == receiver_id)) |
        ((ChatSession.user2_id == current_user.id) & (ChatSession.user1_id == receiver_id))
    ).first()

    if not session:
        return

    message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=encrypted_message
    )
    db.session.add(message)
    db.session.commit()

    emit("message", {
        "username": current_user.username,
        "message": encrypted_message
    }, room=str(receiver_id))
