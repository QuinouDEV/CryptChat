import secrets
from flask import Blueprint, render_template, request
from flask_socketio import emit
from flask_login import current_user, login_required
from app.models import User, ChatSession, Message, caesar_encrypt, caesar_decrypt
from datetime import datetime, timedelta
from app import socketio, db



chat_bp = Blueprint("chat", __name__, url_prefix="/chat")


def generate_diffie_hellman_key():
    prime = 23
    base = 5

    private_key = secrets.randbelow(prime)
    public_key = pow(base, private_key, prime)

    return private_key, public_key


@chat_bp.route("/exchange_key/<string:receiver_id>", methods=["POST"])
@login_required
def exchange_key(receiver_id):
    print(f"Exchange key requested for user {receiver_id}")
    receiver = User.query.filter_by(uuid=receiver_id).first()
    if not receiver:
        print("Utilisateur introuvable") 
        return {"error": "Utilisateur introuvable"}, 404

    session = ChatSession.query.filter(
        (ChatSession.user1_id == current_user.id) & (ChatSession.user2_id == receiver.id) |
        (ChatSession.user2_id == current_user.id) & (ChatSession.user1_id == receiver.id)
    ).first()

    if not session:
        private_key_sender, public_key_sender = generate_diffie_hellman_key()
        private_key_receiver, public_key_receiver = generate_diffie_hellman_key()
        shared_key = pow(public_key_receiver, private_key_sender, 23)

        session = ChatSession(
            user1_id=current_user.id, 
            user2_id=receiver.id, 
            shared_key=str(shared_key),
            key_generated_at=datetime.utcnow()
        )
        db.session.add(session)
        db.session.commit()

        print(f"Retour de public_key: {public_key_sender}")
        return {"public_key": public_key_sender}, 200

    time_diff = datetime.utcnow() - session.key_generated_at
    if time_diff > timedelta(minutes=15): 
        print("La clé est trop vieille, génération d'une nouvelle clé.")
        private_key_sender, public_key_sender = generate_diffie_hellman_key()
        private_key_receiver, public_key_receiver = generate_diffie_hellman_key()
        shared_key = pow(public_key_receiver, private_key_sender, 23)

        session.shared_key = str(shared_key)
        session.key_generated_at = datetime.utcnow()
        db.session.commit()

        return {"public_key": public_key_sender}, 200

    print(f"Session existante trouvée, clé partagée : {session.shared_key}")
    return {"public_key": session.shared_key}, 200


@chat_bp.route("/<string:receiver_id>")
@login_required
def chat(receiver_id):
    receiver = User.query.filter_by(uuid=receiver_id).first()
    if not receiver:
        return f"Receiver with ID {receiver_id} not found."

    session = ChatSession.query.filter(
        (ChatSession.user1_id == current_user.id) & (ChatSession.user2_id == receiver.id) |
        (ChatSession.user2_id == current_user.id) & (ChatSession.user1_id == receiver.id)
    ).first()

    if not session:
        return "Aucune session trouvée pour cet utilisateur."

    shared_key = int(session.shared_key) % 26 

    messages = Message.query.filter(
        (Message.sender_id == current_user.id) & (Message.receiver_id == receiver.id) |
        (Message.sender_id == receiver.id) & (Message.receiver_id == current_user.id)
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for msg in messages:
        decrypted_msg = caesar_decrypt(msg.content, shared_key) 
        decrypted_messages.append((msg.sender.username, decrypted_msg))

    return render_template("chat.html", receiver=receiver, messages=decrypted_messages)


@socketio.on("message")
def handle_message(data):
    receiver_id = data.get("receiver_id")
    message_text = data.get("message")

    if not receiver_id or not message_text:
        return 

    session = ChatSession.query.filter(
        ((ChatSession.user1_id == current_user.id) & (ChatSession.user2_id == receiver_id)) |
        ((ChatSession.user2_id == current_user.id) & (ChatSession.user1_id == receiver_id))
    ).first()

    if not session:
        print(f"No shared key found for session between {current_user.id} and {receiver_id}")
        return  

    shared_key = int(session.shared_key) % 26 
    print(f"Shared key: {shared_key}")
    encrypted_message = caesar_encrypt(message_text, shared_key)

    message = Message(sender_id=current_user.id, receiver_id=receiver_id, content=encrypted_message)
    db.session.add(message)
    db.session.commit()

    emit("message", {
        "username": current_user.username,
        "message": encrypted_message
    }, broadcast=True)

