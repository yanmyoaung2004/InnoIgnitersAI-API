from sqlalchemy.orm import Session,joinedload
from datetime import datetime
from models.models import Chat, Message, Image

def create_new_chat(db: Session, user_id: int) -> Chat:
    chat = Chat(user_id=user_id, created_at=datetime.utcnow())
    db.add(chat)
    db.commit()
    db.refresh(chat)
    return chat

def update_chat_title(db: Session, chat_id: int, title: str) -> Chat | None:
    """
    Update the title of a chat.
    Returns the updated Chat object, or None if chat not found.
    """
    chat = db.query(Chat).filter(Chat.unique_id == chat_id).first()
    if not chat:
        return None

    chat.title = title
    db.add(chat)
    db.commit()
    db.refresh(chat)
    return chat

def add_message_to_chat(db: Session, chat_id: int, role: str, content: str, reason: str) -> Message:
    message = Message(chat_id=chat_id, role=role, content=content, reason=reason, time_stamp=datetime.utcnow())
    db.add(message)
    db.commit()
    db.refresh(message)
    return message

def add_image_to_message(db: Session, message_id: int, image_url: str) -> Message:
    image = Image(message_id=message_id, image_url=image_url, time_stamp=datetime.utcnow())
    db.add(image)
    db.commit()
    db.refresh(image)
    return image


def get_all_messages(db: Session, chat_id: int) -> list[Message]:
    return (
        db.query(Message)
        .filter(Message.chat_id == chat_id)
        .order_by(Message.time_stamp.asc())
        .all()
    )

def get_chat_by_id(db: Session, chat_id: int) -> Chat | None:
    return db.query(Chat).filter(Chat.unique_id == chat_id).first()

def get_chat_messages(db: Session, chat_id: int) -> list[Message]:
    return db.query(Message).options(joinedload(Message.images)).filter(Message.chat_id == chat_id).order_by(Message.time_stamp.asc()).all()

def get_user_chats(db: Session, user_id: int) -> list[Chat]:
    return db.query(Chat).filter(Chat.user_id == user_id).order_by(Chat.created_at.desc()).all()

def delete_chat(db: Session, chat_id: int) -> bool:
    """
    Delete a chat by unique_id. All related messages will be deleted automatically
    because of cascade settings.
    
    Returns True if deleted, False if not found.
    """
    chat = db.query(Chat).filter(Chat.unique_id == chat_id).first()
    if not chat:
        return False

    db.delete(chat)
    db.commit()
    return True