import json
from typing import List, Optional
from fastapi import WebSocket
from groq import Groq
from models.schemas import HistoryMessage
import os


def flatten_user_message(msg):
    """Flatten a user message content into a string."""
    content = msg.get("content")
    if isinstance(content, str):
        return msg
    elif isinstance(content, list):
        combined = ""
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    combined += item.get("text", "") + " "
                elif item.get("type") == "image_url":
                    combined += f"[image: {item.get('image_url', {}).get('url', '')}] "
            else:
                combined += str(item) + " "
        msg["content"] = combined.strip()
    else:
        msg["content"] = str(content)
    return msg

async def stream_image_responder(
    ws: WebSocket,
    imageUrl: Optional[str],
    query: str,
    message: List[HistoryMessage] = [],
):
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    user_message = {
        "role": "user",
        "content": [{"type": "text", "text": query}]
    }

    if imageUrl:
        user_message["content"].append({
            "type": "image_url",
            "image_url": {"url": imageUrl}
        })

    message.append(user_message)

    stream = client.chat.completions.create(
        model="meta-llama/llama-4-scout-17b-16e-instruct",
        messages=message,
        temperature=1,
        max_completion_tokens=1024,
        top_p=1,
        stream=True,
    )

    answer_text = ""

    for chunk in stream:
        delta = chunk.choices[0].delta
        if delta and delta.content:
            answer_text += delta.content
            await ws.send_text(json.dumps({
                "type": "answer",
                "data": delta.content
            }))
    last_msg = message.pop()
    last_msg = flatten_user_message(last_msg)
    message.append(last_msg)

    return {
        "reason": "",
        "answer": answer_text
    }