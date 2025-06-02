# app/messaging/routes.py
# Contains routes for sending, receiving, and managing messages.
from flask import request, jsonify
from . import messaging_bp
from app.models import User, Message, MessageRecipient, Tag, db # Removed MessageTag as it's an association table
from app.extensions import db
from flask_jwt_extended import jwt_required, get_jwt_identity, current_user
from sqlalchemy.orm import aliased
from sqlalchemy import or_

def get_current_user_id_from_identity(): # Renamed to avoid conflict if current_user.id is preferred
    """Helper function to get the current user's ID from JWT string identity."""
    identity_str = get_jwt_identity() # Returns user ID as string
    if identity_str:
        try:
            return int(identity_str)
        except ValueError:
            return None # Should not happen if token creation is correct
    return None

def is_admin_user_from_current_user_obj(): # Renamed for clarity
    """
    Helper function to check if the current user is an admin.
    Relies on current_user being populated by user_lookup_loader.
    """
    # current_user is a proxy to the object returned by user_lookup_loader (User instance or None)
    if isinstance(current_user, User):
        return current_user.is_admin
    return False

# --- Message Sending Endpoints ---
@messaging_bp.route('/messages/private', methods=['POST'])
@jwt_required()
def send_private_message():
    """
    Sends a private message from the authenticated user to a specified recipient.
    Expects JSON: {"recipient_username": "user2", "content": "Hello!"}
    """
    # current_user is the User object loaded by user_lookup_loader
    sender_id = current_user.id
    data = request.get_json()

    if not data or not data.get('recipient_username') or not data.get('content'):
        return jsonify({"msg": "Missing recipient_username or content"}), 400

    recipient_username = data['recipient_username']
    content = data['content']

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({"msg": f"Recipient user '{recipient_username}' not found"}), 404

    if recipient.id == sender_id:
        return jsonify({"msg": "Cannot send a private message to yourself this way."}), 400

    try:
        message = Message(sender_id=sender_id, content=content, message_type='private')
        db.session.add(message)
        db.session.flush()

        message_recipient = MessageRecipient(message_id=message.id, recipient_id=recipient.id)
        db.session.add(message_recipient)

        db.session.commit()
        return jsonify({"msg": "Private message sent successfully", "message_id": message.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to send private message", "error": str(e)}), 500

@messaging_bp.route('/messages/group', methods=['POST'])
@jwt_required()
def send_group_message():
    """
    Sends a group message from the authenticated user to specified recipients.
    Expects JSON: {"recipient_usernames": ["user2", "user3"], "content": "Group update!"}
    """
    sender_id = current_user.id
    data = request.get_json()

    if not data or not data.get('recipient_usernames') or not data.get('content'):
        return jsonify({"msg": "Missing recipient_usernames or content"}), 400

    recipient_usernames = data['recipient_usernames']
    content = data['content']

    if not isinstance(recipient_usernames, list) or not recipient_usernames:
        return jsonify({"msg": "recipient_usernames must be a non-empty list"}), 400

    recipients = User.query.filter(User.username.in_(recipient_usernames)).all()
    if len(recipients) != len(recipient_usernames):
        found_usernames = {r.username for r in recipients}
        missing_usernames = [u for u in recipient_usernames if u not in found_usernames]
        return jsonify({"msg": f"Some recipient users not found: {missing_usernames}"}), 404

    recipient_ids = {r.id for r in recipients if r.id != sender_id}
    if not recipient_ids:
         return jsonify({"msg": "No valid recipients for group message (excluding self or none found)."}), 400

    try:
        message = Message(sender_id=sender_id, content=content, message_type='group')
        db.session.add(message)
        db.session.flush()

        for recipient_id_val in recipient_ids: # Renamed to avoid conflict
            message_recipient = MessageRecipient(message_id=message.id, recipient_id=recipient_id_val)
            db.session.add(message_recipient)

        db.session.commit()
        return jsonify({"msg": "Group message sent successfully", "message_id": message.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to send group message", "error": str(e)}), 500

@messaging_bp.route('/messages/public', methods=['POST'])
@jwt_required()
def send_public_message():
    """
    Sends a public message from the authenticated user with specified tags.
    Expects JSON: {"tags": ["announcement", "release"], "content": "New version out!"}
    """
    sender_id = current_user.id
    data = request.get_json()

    if not data or not data.get('content'):
        return jsonify({"msg": "Missing content"}), 400

    tag_names = data.get('tags', [])
    content = data['content']

    if not isinstance(tag_names, list):
        return jsonify({"msg": "tags must be a list of strings"}), 400

    try:
        message = Message(sender_id=sender_id, content=content, message_type='public')
        db.session.add(message)
        db.session.flush()

        for tag_name in tag_names:
            tag = Tag.query.filter_by(name=tag_name.lower()).first()
            if not tag:
                tag = Tag(name=tag_name.lower())
                db.session.add(tag)
                db.session.flush()
            message.tags.append(tag)

        db.session.commit()
        return jsonify({"msg": "Public message sent successfully", "message_id": message.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to send public message", "error": str(e)}), 500

# --- Message Retrieval Endpoints ---
@messaging_bp.route('/messages/private', methods=['GET'])
@jwt_required()
def get_private_messages():
    """Retrieves private messages for the authenticated user (both sent and received)."""
    auth_user_id = current_user.id # User ID from loaded User object

    sent_private = Message.query.filter_by(sender_id=auth_user_id, message_type='private').order_by(Message.timestamp.desc()).all()

    received_private_query = db.session.query(Message).join(MessageRecipient).\
        filter(MessageRecipient.recipient_id == auth_user_id, Message.message_type == 'private').\
        order_by(Message.timestamp.desc())
    received_private = received_private_query.all()

    messages_data = []
    # Process sent messages
    for msg in sent_private:
        mr = MessageRecipient.query.filter_by(message_id=msg.id).first() # Should be only one for private
        recipient_username = User.query.get(mr.recipient_id).username if mr else "Unknown"
        messages_data.append({
            "id": msg.id, "sender_username": current_user.username, # Sender is the authenticated user
            "recipient_username": recipient_username,
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })

    # Process received messages
    for msg in received_private:
        sender_user = User.query.get(msg.sender_id) # Fetch sender User object
        sender_username = sender_user.username if sender_user else "Unknown"
        messages_data.append({
            "id": msg.id, "sender_username": sender_username,
            "recipient_username": current_user.username, # Recipient is the authenticated user
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })

    messages_data.sort(key=lambda x: x['timestamp'], reverse=True)
    final_messages = []
    seen_ids = set()
    for msg_data in messages_data:
        if msg_data['id'] not in seen_ids:
            final_messages.append(msg_data)
            seen_ids.add(msg_data['id'])

    return jsonify(final_messages), 200


@messaging_bp.route('/messages/group', methods=['GET'])
@jwt_required()
def get_group_messages():
    """Retrieves group messages where the authenticated user is either the sender or a recipient."""
    auth_user_id = current_user.id

    sent_group = Message.query.filter_by(sender_id=auth_user_id, message_type='group').all()

    received_group_query = db.session.query(Message).join(MessageRecipient).\
        filter(MessageRecipient.recipient_id == auth_user_id, Message.message_type == 'group')
    received_group = received_group_query.all()

    all_user_messages = list(set(sent_group + received_group))
    all_user_messages.sort(key=lambda m: m.timestamp, reverse=True)

    messages_data = []
    for msg in all_user_messages:
        sender_obj = User.query.get(msg.sender_id) # Fetch sender User object
        sender_username = sender_obj.username if sender_obj else "Unknown"
        recipient_usernames = [User.query.get(mr.recipient_id).username for mr in msg.recipients_link.all() if User.query.get(mr.recipient_id)]
        messages_data.append({
            "id": msg.id, "sender_username": sender_username,
            "recipients_usernames": recipient_usernames,
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })
    return jsonify(messages_data), 200

@messaging_bp.route('/messages/public', methods=['GET'])
@jwt_required()
def get_public_messages():
    """
    Retrieves public messages. Filters by subscribed tags if no 'tags' query param.
    Optionally filter by query param `tags=tag1,tag2`.
    """
    auth_user = current_user # Authenticated User object

    query_tags_str = request.args.get('tags')
    query = Message.query.filter_by(message_type='public')

    if query_tags_str:
        query_tag_names = [t.strip().lower() for t in query_tags_str.split(',')]
        query = query.join(Message.tags).filter(Tag.name.in_(query_tag_names))
    elif auth_user.subscribed_tags:
        subscribed_tag_ids = [tag.id for tag in auth_user.subscribed_tags]
        if subscribed_tag_ids: # Ensure list is not empty before filtering
             query = query.join(Message.tags).filter(Tag.id.in_(subscribed_tag_ids))

    messages = query.order_by(Message.timestamp.desc()).all()

    messages_data = []
    for msg in messages:
        sender_obj = User.query.get(msg.sender_id)
        sender_username = sender_obj.username if sender_obj else "Unknown"
        message_tags = [tag.name for tag in msg.tags]
        messages_data.append({
            "id": msg.id, "sender_username": sender_username, "tags": message_tags,
            "content": msg.content, "timestamp": msg.timestamp.isoformat(), "type": msg.message_type
        })
    return jsonify(messages_data), 200

# --- Tag Subscription Endpoints ---
@messaging_bp.route('/tags/subscribe', methods=['POST'])
@jwt_required()
def subscribe_to_tags():
    """
    Subscribes the authenticated user to specified tags.
    Expects JSON: {"tags": ["news", "updates"]}
    """
    auth_user = current_user
    data = request.get_json()

    if not data or not isinstance(data.get('tags'), list):
        return jsonify({"msg": "Missing 'tags' list in request"}), 400

    tag_names_to_subscribe = data['tags']

    try:
        for tag_name in tag_names_to_subscribe:
            tag = Tag.query.filter_by(name=tag_name.lower()).first()
            if not tag:
                tag = Tag(name=tag_name.lower())
                db.session.add(tag)
            if tag not in auth_user.subscribed_tags: # Check association
                auth_user.subscribed_tags.append(tag)
        db.session.commit()
        current_subscriptions = [t.name for t in auth_user.subscribed_tags]
        return jsonify({"msg": "Successfully subscribed to tags", "current_subscriptions": current_subscriptions}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to subscribe to tags", "error": str(e)}), 500

@messaging_bp.route('/tags/unsubscribe', methods=['POST'])
@jwt_required()
def unsubscribe_from_tags():
    """
    Unsubscribes the authenticated user from specified tags.
    Expects JSON: {"tags": ["news"]}
    """
    auth_user = current_user
    data = request.get_json()

    if not data or not isinstance(data.get('tags'), list):
        return jsonify({"msg": "Missing 'tags' list in request"}), 400

    tag_names_to_unsubscribe = data['tags']

    try:
        for tag_name in tag_names_to_unsubscribe:
            tag = Tag.query.filter_by(name=tag_name.lower()).first()
            if tag and tag in auth_user.subscribed_tags: # Check association
                auth_user.subscribed_tags.remove(tag)
        db.session.commit()
        current_subscriptions = [t.name for t in auth_user.subscribed_tags]
        return jsonify({"msg": "Successfully unsubscribed from tags", "current_subscriptions": current_subscriptions}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to unsubscribe from tags", "error": str(e)}), 500

# --- Message Deletion Endpoint ---
@messaging_bp.route('/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    """
    Deletes a message based on its type and user permissions.
    - Private: deletable by sender, receiver, or admin.
    - Group: deletable by sender or admin.
    - Public: deletable by sender or admin.
    """
    auth_user_id = current_user.id
    is_current_user_admin = is_admin_user_from_current_user_obj() # Use updated helper

    message = Message.query.get(message_id)
    if not message:
        return jsonify({"msg": "Message not found"}), 404

    can_delete = False
    if is_current_user_admin:
        can_delete = True
    elif message.sender_id == auth_user_id:
        can_delete = True
    elif message.message_type == 'private':
        recipient_link = MessageRecipient.query.filter_by(message_id=message.id, recipient_id=auth_user_id).first()
        if recipient_link:
            can_delete = True

    if not can_delete:
        return jsonify({"msg": "You do not have permission to delete this message"}), 403

    try:
        db.session.delete(message)
        db.session.commit()
        return jsonify({"msg": f"Message {message_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Failed to delete message", "error": str(e)}), 500


