from agents.detection_agent import DetectionAgent
from agents.knowledge_agent import KnowledgeAgent
from tools.detection_tool import DetectionTool
from typing import Literal, List
from groq import Groq
from fastapi import  WebSocket
import os
import dspy
import json
from models.schemas import HistoryMessage
from database.database import  engine
from sqlalchemy.orm import sessionmaker
from database.crud import update_chat_title
from agents.image_agent import stream_image_responder



lm_util = dspy.LM(
    model="groq/openai/gpt-oss-20b",
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
    temperature=0
)

dspy.configure_cache(
    enable_disk_cache=True,
    enable_memory_cache=True
)

dspy.configure(lm=lm_util)


class IntentClassificationJudge(dspy.Signature):
    """
    Classifies the user's query into one of three intents:
    - 'knowledge_agent' → For cybersecurity-related informational or educational questions
      (e.g., best practices, security concepts, mitigation techniques).
    - 'detection_agent' → For cybersecurity-related detection, analysis, or threat investigation requests
      (e.g., detecting malware, analyzing suspicious activity, running scans).
    - 'normal_conversation' → For general knowledge, casual conversation, or topics unrelated to cybersecurity.

    🌍 Language Support:
    - Handles both **English** and **Burmese (မြန်မာ)** queries.

    Rules:
    1. If the query is about cybersecurity knowledge (in English or Burmese) → return 'knowledge_agent'.
       - Example (EN): "What are the best practices for password security?"
       - Example (MM): "လုံခြုံသော စကားဝှက် တည်ဆောက်ရန် အကောင်းဆုံးနည်းလမ်းများက ဘာတွေပါလဲ။"
    2. If the query is about detection/analysis in cybersecurity → return 'detection_agent'.
       - Example (EN): "Can you detect if this file is malware?"
       - Example (MM): "ဒီဖိုင်ကို မော်လ်ဝဲလား ဆိုတာ စိစစ်ပေးနိုင်မလား။"
    3. If unrelated to cybersecurity or casual talk → return 'normal_conversation'.
       - Example (EN): "What’s the weather like today?"
       - Example (MM): "ဒီနေ့ မိုးလေဝသဘယ်လိုလဲ။"
    """
    query: str = dspy.InputField(description="The original user query (English or Burmese)")
    intent: Literal['detection_agent', 'knowledge_agent', 'normal_conversation'] = dspy.OutputField(
        description="One of: 'detection_agent', 'knowledge_agent', or 'normal_conversation'"
    )

class ChatTitleCreator(dspy.Signature):
    """
    Generate a concise title for a chat based on its content.
    The title should summarize the chat's main topic in a few words.
    Can handle English, Burmese, or mixed messages.
    """
    content: str = dspy.InputField(
        description="Concatenated user and assistant messages from the chat"
    )
    title: str = dspy.OutputField(
        description="Generated chat title summarizing the conversation"
    )


SYSTEM_MESSAGE = [{
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
        }]

class MasterAgent(dspy.Module):
    def __init__(self, metadata=None):
        self.detection_agent = DetectionAgent({'DetectionTool': DetectionTool()})
        self.knowledge_agent = KnowledgeAgent()
        self.intent_judge = dspy.ChainOfThought(IntentClassificationJudge)
        self.chat_title_generator = dspy.ChainOfThought(ChatTitleCreator)
        self.metadata = metadata or {
            "bot_name": "InnoIgnitorsAI",
            "developer": "InnoIgnitorsAI Developer Team"
        }
        groq_api_key = os.getenv("GROQ_API_KEY")
        if not groq_api_key:
            raise ValueError("GROQ_API_KEY environment variable is not set")
        self.client = Groq(api_key=groq_api_key)

    async def forward(self, query: str, reasoning_include: bool, ws: WebSocket, chat_id: int, fileUrl: str = None, history: List[HistoryMessage] = [], imageUrl : str = None):
        classified_intent = self.intent_judge(query=query)
        print("Detected intent:", classified_intent.intent)
        if imageUrl is not None:
            print("imageagent call")
            result = await stream_image_responder(ws=ws, imageUrl=imageUrl, query=query, message=history)
        elif fileUrl is not None:
            print("file url scan")
            result = await self.detection_agent.detect_file(query=query, fileUrl=fileUrl, reasoning_include=reasoning_include, ws=ws, message=history)
        elif classified_intent.intent == "detection_agent":
            result = await self.detection_agent.plan_and_execute(query=query, 
                                                        message=history,
                                                        reasoning_include=reasoning_include,
                                                        ws=ws)
        elif classified_intent.intent == "knowledge_agent":
            result = await self.knowledge_agent.aforward(query=query,
                                                         intent=classified_intent.intent,
                                                         history=history,
                                                         reasoning_include=reasoning_include,
                                                         ws=ws)
        else:
            result = await self.knowledge_agent.aforward(query=query,
                                                         intent=classified_intent.intent,
                                                         history=history,
                                                         reasoning_include=reasoning_include,
                                                         ws=ws)
        
        chat_messages = history[2:]
        if 1 <= len(chat_messages) < 4:
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            db = SessionLocal()
            chat_content = "\n".join([f"{m['role']}: {m['content']}" for m in chat_messages])
            chat_title = self.chat_title_generator(content=chat_content)
            await ws.send_text(json.dumps({"type": "title", "title": chat_title.title, 'chatId' : chat_id}))
            update_chat_title(db=db, chat_id=chat_id, title=chat_title.title)
        return result