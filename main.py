from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from config.config import CORS_ORIGINS
from database.database import Base, engine
from routes import routes
import json
from dotenv import load_dotenv
from agents.master_agent import MasterAgent
from database.crud import create_new_chat, add_message_to_chat, get_chat_messages, get_user_chats, get_all_messages, get_chat_by_id, delete_chat, add_image_to_message
from database.deps import get_user_id_from_token_dependency, get_current_user
from sqlalchemy.orm import sessionmaker
from models.models import User, Message, Chat
from models.schemas import ChatOut, MessageOut
from sqlalchemy import func
from fastapi.responses import JSONResponse
import shutil
from fastapi.staticfiles import StaticFiles
import os
import uuid

# Create DB tables
Base.metadata.create_all(bind=engine)

load_dotenv()
app = FastAPI(title="InnoIgnitersAI", version="1.0")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
master_agent = MasterAgent()

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("FRONT_END_ORIGIN"),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# Include routers
app.include_router(routes.router)


active_chats: dict[int, str] = {}            
chat_histories: dict[str, list[dict]] = {} 

system_messages = [
    {
        "role": "system",
        "content": """You are InnoIgnitorsAI, developed by InnoIgnitors AI Developer Team. 
        Answer questions in a warm, chatty, and friendly way 😊. 
        Use the provided context to be accurate and helpful. 
        Keep it conversational and approachable, with occasional emojis.
        IMPORTANT: When asked about yourself, do NOT mention OpenAI or the language model. 
        Only talk about being InnoIgnitorsAI and the InnoIgnitors AI Developer Team."""
    },
    {
        "role": "system",
        "content": """CRUCIAL INSTRUCTION FOR REASONING:
        When generating reasoning (internal thought process), 
        do NOT include instructions about tone, style, or being friendly. 
        Do NOT include system role reminders or emojis. 
        Only reason about the user's query content itself and its logical analysis."""
    }
]


@app.websocket("/chat")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    db = SessionLocal()
    try:
        while True:
            prompt_json = await ws.receive_text()
            data = json.loads(prompt_json)
            query = data.get("query")
            include_reasoning = data.get("includeReasoning", False)
            chatId = data.get("currentChatId", None)
            fileUrl = data.get("fileUrl", None)
            imageUrl = data.get("imageUrl", None)
            token = data.get("token", None)
            user_id = get_user_id_from_token_dependency(token, db=db)
            prev_chat = active_chats.get(user_id)
            if prev_chat != chatId:
                if chatId and chatId not in chat_histories:
                    chat = get_chat_by_id(db, chatId)
                    if chat:
                        messages = get_all_messages(db, chat.id)
                        chat_histories[chatId] = [
                            {"role": m.role, "content": m.content}
                            for m in messages
                        ]

                active_chats[user_id] = chatId
            if chatId is None and token is None:
                print("no account")
                result = await master_agent(
                    query=query,
                    reasoning_include=include_reasoning,
                    ws=ws,
                    chat_id=chatId,
                    fileUrl=fileUrl,
                    imageUrl=imageUrl,
                    history=system_messages
                )
            elif chatId is None and token is not None:
                chat = create_new_chat(db, user_id)
                await ws.send_text(json.dumps({
                    "type": "new_chat",
                    "id": chat.id,
                    "unique_id" : chat.unique_id,
                    "title" : chat.title,
                }))
                
                chat_histories[chat.unique_id] = system_messages.copy()
                active_chats[user_id] = chat.unique_id
                message = add_message_to_chat(db=db, chat_id=chat.id, role="user", content=query, reason=None)
                if imageUrl is not None:
                    print(imageUrl)
                    add_image_to_message(db=db, message_id=message.id, image_url=imageUrl)
                result = await master_agent(
                    query=query,
                    reasoning_include=include_reasoning,
                    ws=ws,
                    chat_id=chat.unique_id,
                    fileUrl=fileUrl,
                    imageUrl=imageUrl,
                    history=chat_histories[chat.unique_id]
                )
                add_message_to_chat(db=db, chat_id=chat.id, role="assistant", content=result["answer"], reason=result.get("reason"))
                chat_histories[chat.unique_id].append({"role": "assistant", "content": result["answer"]})
            else:
                chat = get_chat_by_id(db, chatId)
                message = add_message_to_chat(db=db, chat_id=chat.id, role="user", content=query, reason=None)
                if imageUrl is not None:
                    print(imageUrl)
                    add_image_to_message(db=db, message_id=message.id, image_url=imageUrl)
                result = await master_agent(
                    query=query,
                    reasoning_include=include_reasoning,
                    ws=ws,
                    chat_id=chatId,
                    imageUrl=imageUrl,
                    fileUrl=fileUrl,
                    history=chat_histories[chatId]
                )
                add_message_to_chat(db=db, chat_id=chat.id, role="assistant", content=result["answer"], reason=result.get("reason"))
                chat_histories[chatId].append({"role": "assistant", "content": result["answer"]})

            await ws.send_text(json.dumps({"type": "done"}))
    except WebSocketDisconnect:
        print("Client disconnected")
    finally:
        db.close()



@app.get("/chats/{chat_id}", response_model=ChatOut)
def get_chat(chat_id: str, current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    chat = db.query(Chat).filter(Chat.unique_id == chat_id, Chat.user_id == current_user.id).first()
    if not chat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat not found")
    messages = get_chat_messages(db, chat.id)
    messages_out = [
        MessageOut(
            id=m.id,
            role=m.role,
            content=m.content,
            reasoning=m.reason,
            imageUrl=m.images[0].image_url if m.images else None,
            time_stamp=str(m.time_stamp)
        )
        for m in messages
    ]
    db.close() 
    return ChatOut(id=chat.id, created_at=str(chat.created_at), messages=messages_out)


@app.delete("/chat/delete/{chat_id}", response_model=ChatOut)
def get_chat(chat_id: str, current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    chat = db.query(Chat).filter(Chat.unique_id == chat_id, Chat.user_id == current_user.id).first()
    if not chat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat not found")
    delete_chat(db, chat_id)
    db.close() 
    return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "message": "Chat deleted successfully"},
        )


@app.get("/chats")
def list_chats(current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    print(current_user.id)
    chats = get_user_chats(db, current_user.id)
    result = []
    for chat in chats:
        last_msg = db.query(Message).filter(Message.chat_id == chat.id) \
                                        .order_by(Message.time_stamp.desc()) \
                                        .first()
        message_count = db.query(func.count(Message.id)) \
                          .filter(Message.chat_id == chat.id) \
                          .scalar()
        db.close() 
        result.append({
            "id": chat.id,
            "title": chat.title,
            "unique_id": chat.unique_id,
            "lastMessage": last_msg.content if last_msg else "",
            "timestamp": last_msg.time_stamp.isoformat() if last_msg else chat.created_at.isoformat(),
            "messageCount": message_count
        })
    return result

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename)[1] 
    safe_name = f"{uuid.uuid4().hex}{ext}"  
    
    file_path = os.path.join(UPLOAD_DIR, safe_name)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")
    
    file_url = f"/uploads/{safe_name}"
    return JSONResponse({
        "original_filename": file.filename,
        "saved_filename": safe_name,
        "file_url": file_url,
        "message": "File uploaded successfully!"
    })