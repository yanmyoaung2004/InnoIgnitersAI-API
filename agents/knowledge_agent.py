import os
import dspy
from typing import Literal, Optional, List, Any
import dspy
from tools.mitre_tool import SafeMitreTool
from tools.siem_tool import SIEMTool
from tools.cve_tool import CVETool
from tools.myanmar_law_tool import MyanmarLawAgentTool
from tools.web_search import WebSearchTool
from agents.tool_agent import ToolAgent
import json
from fastapi import  WebSocket
from groq import Groq
from models.schemas import HistoryMessage
from typing import Optional



class RefineAndCheckConfidence(dspy.Signature):
    """
    Combine query refinement and zero-shot confidence check in one step.

    Purpose:
    - Refine a user query into a clearer, more effective version for cybersecurity experts or general conversation.
    - Keep the query in the same language as the input. Do not translate.
    - Determine if the LLM can answer the query confidently without external tools.

    Special rules:
    - For greetings or basic pleasantries (e.g., "Hi", "Hello", "မင်္ဂလာပါ"),
      always return intent='yes' with high confidence, because the model can always reply.
    - For other queries, evaluate whether the LLM can answer accurately based on its knowledge.

    Output JSON format:
    {
        "refined_query": "<optimized query in the original language>",
        "intent": "yes" or "no",
        "confidence": <float between 0.0 and 1.0>
    }
    """
    original_query: str = dspy.InputField(desc="Original user question or message")
    refined_query: str = dspy.OutputField(desc="Improved or clarified version of the query")
    intent: Literal['yes', 'no'] = dspy.OutputField(
        desc="Indicates whether the LLM can answer confidently ('yes' or 'no')"
    )
    confidence: Optional[float] = dspy.OutputField(
        desc="Confidence score between 0.0 and 1.0 (optional, but recommended)"
    )


class ChattyFriendlyResponse(dspy.Signature):
    """
    [SYSTEM]
    You are InnoIgnitorsAI, developed by InnoIgnitors AI Developer Team.

    Answer questions in a warm, chatty, and friendly way 😊.
    Keep the tone conversational and approachable, with occasional emoji for personality."""
    refined_query: str = dspy.InputField(description="Optimized or clarified version of the user's question")
    history: dspy.History = dspy.InputField()
    answer: str = dspy.OutputField(description="A friendly, conversational response with light emoji and warmth")

    
class CybersecurityResponse(dspy.Signature):
    """
    [SYSTEM]
    You are InnoIgnitorsAI, developed by InnoIgnitors AI Developer Team.

    Answer cybersecurity questions as an expert in the field in a warm, chatty, and friendly way 😊.
    Keep the tone conversational and approachable, with occasional emoji for personality."""
    refined_query: str = dspy.InputField(desc="Optimized question to answer")
    history: dspy.History = dspy.InputField()
    answer: str = dspy.OutputField(desc="Comprehensive response to the query")


async def stream_response_contextual_respond(ws: WebSocket, include_reasoning: bool, client: Groq,  message: List[HistoryMessage] = [], chatModel: str = None,):
    chatModel = chatModel or os.getenv("LLM_MODEL")
    stream = client.chat.completions.create(
        model=chatModel,
        reasoning_effort=os.getenv("REASONING_EFFORT"),
        include_reasoning=include_reasoning,
        stream=True,
        messages = message
    )
    reasoning_text = ""
    answer_text = ""
    reasoning_ended = False

    for chunk in stream:
        delta = chunk.choices[0].delta
        if delta.reasoning:
            reasoning_text += delta.reasoning
            await ws.send_text(json.dumps({"type": "reasoning", "data": delta.reasoning}))
        if delta.content:
            if not reasoning_ended:
                reasoning_ended = True
            answer_text += delta.content
            await ws.send_text(json.dumps({"type": "answer", "data": delta.content}))
    return {
       "reason" : reasoning_text,
       "answer" : answer_text
    }

    
class KnowledgeAgent(dspy.Module):
  def __init__(self):
    self.refine_and_check = dspy.ChainOfThought(RefineAndCheckConfidence)
    self.mitre = SafeMitreTool()
    self.cve = CVETool()
    self.myanmar_cyber_law = MyanmarLawAgentTool()
    self.siem = SIEMTool([
        {"event_id": "E001", "timestamp": "2025-08-24T08:00:00", "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5", "user": "admin", "severity": "HIGH", "message": "Failed login attempt"},
        {"event_id": "E002", "timestamp": "2025-08-24T08:05:00", "source_ip": "10.1.1.50",
        "destination_ip": "10.0.0.5", "user": "guest", "severity": "HIGH", "message": "SSL session reuse detected"},
        {"event_id": "E003", "timestamp": "2025-08-24T08:10:00", "source_ip": "192.168.1.20",
        "destination_ip": "10.0.0.6", "user": "admin", "severity": "LOW", "message": "File download completed"}
    ])
    self.websearch_tool = WebSearchTool()
    self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))

  async def aforward(self, query: str, intent: str, history: List[HistoryMessage], reasoning_include : bool, ws:WebSocket):
    if intent == 'normal_conversation':
      history.append({"role": "user", "content": query})
      return await stream_response_contextual_respond(ws, reasoning_include, self.client, history, os.getenv("NORMAL_CHAT_MODEL"))
    else:
      confident = self.refine_and_check(original_query=query)
      if confident.intent == 'yes' and (confident.confidence or 0) > 0.8:
        history.append({"role": "user", "content": confident.refined_query})
        return await stream_response_contextual_respond(ws, reasoning_include, self.client, history)

      else:
        tools_dict = {
            'MITRE': self.mitre,
            'CVE': self.cve,
            'SIEM': self.siem,
            # 'Threat Intelligence': threat_tool,
            'Websearch': self.websearch_tool,
            'MyanmarLaw' : self.myanmar_cyber_law
        }
        agent = ToolAgent(tools=tools_dict)
        context = agent.plan_and_execute(confident.refined_query)
        contextual_query = f"{context}\n\nUser Query: {query}"
        history.append({"role": "user", "content": contextual_query})
        return await stream_response_contextual_respond(ws, reasoning_include, self.client, history)
    

