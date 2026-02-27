# app/models.py
# This file defines the SQLAlchemy database models for the application.
from datetime import datetime, timezone
from .extensions import db, bcrypt # bcrypt for password checking in User model

message_tags_association = db.Table('message_tags',
    db.Column('message_id', db.Integer, db.ForeignKey('message.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

user_tag_subscriptions_association = db.Table('user_tag_subscriptions',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_private_messages = db.relationship('MessageRecipient', backref='recipient_user', lazy='dynamic')
    subscribed_tags = db.relationship(
        'Tag',
        secondary=user_tag_subscriptions_association,
        lazy='subquery',
        backref=db.backref('subscribers', lazy=True)
    )

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} (Admin: {self.is_admin})>'

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    message_type = db.Column(db.String(20), nullable=False)

    recipients_link = db.relationship(
        'MessageRecipient',
        backref='message_info',
        lazy='dynamic', cascade="all, delete-orphan"
    )
    tags = db.relationship(
        'Tag',
        secondary=message_tags_association,
        lazy='subquery',
        backref=db.backref('messages_with_tag', lazy=True)
    )

    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} type {self.message_type}>'

class MessageRecipient(db.Model):
    """
    Stores recipients for private and group messages.
    For a private message, there will be one entry.
    For a group message, there will be multiple entries (one for each recipient).
    """
    __tablename__ = 'message_recipient'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<MessageRecipient for Message {self.message_id} to User {self.recipient_id}>'

class Tag(db.Model):
    """Tag model for categorizing public messages."""
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f'<Tag {self.name}>'

