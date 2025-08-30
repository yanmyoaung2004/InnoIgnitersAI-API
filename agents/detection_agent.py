import dspy
import concurrent.futures
from typing import Dict, List, Any
from groq import Groq
import re
import os
import json
from fastapi import  WebSocket
from models.schemas import HistoryMessage




class DetectionPlanner(dspy.Signature):
    """
    DetectionPlanner analyzes a user query for detection requests and generates
    a step-by-step execution plan.

    Inputs:
        query: The user input describing what to detect (URL(s), file(s)).

    Outputs:
        tool_plan: Dict mapping execution steps to tool calls with functions and params. Each call specifies:
            - tool: 'DetectionTool'
            - function: 'detect_url: {"url": "..."}' or 'detect_file : {"file_path": "..."}', 'detect_mail:{"email_content":"..."}'
            - Params dict must match the required parameters for the function.
            - Steps are sequential; outputs from prior steps can inform later ones if needed, but the plan is generated upfront.   
    """
    query: str = dspy.InputField(desc="User query for detection")
    tool_plan: dict = dspy.OutputField(desc="Structured detection plan")

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

class DetectionAgent:
    def __init__(self, tools: Dict[str, Any]):
        """
        tools: e.g., {'DetectionTool': detection_tool_instance}
        """
        self.planner = dspy.ChainOfThought(DetectionPlanner)
        self.tools = tools
        self.detection_groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))


    def _validate_plan(self, tool_plan: Dict) -> Dict[int, List[Dict[str, Any]]]:
        """
        Validates and normalizes the plan:
        - Extracts integer step numbers
        - Wraps single dict tool calls into lists
        """
        normalized_plan = {}
        for step, calls in tool_plan.items():
            # Extract integer from keys like "step1"
            if isinstance(step, str):
                match = re.search(r'\d+', step)
                if not match:
                    raise ValueError(f"Cannot parse step number from '{step}'")
                step_num = int(match.group())
            else:
                step_num = step

            if step_num < 1:
                raise ValueError(f"Step number must be >= 1, got {step_num}")

            if isinstance(calls, dict):
                calls = [calls]
            elif not isinstance(calls, list):
                raise ValueError(f"Tool calls for step {step_num} must be a list or dict")

            for call in calls:
                if not all(k in call for k in ['tool', 'function', 'params']):
                    raise ValueError(f"Invalid tool call format in step {step_num}: {call}")
                if call['tool'] not in self.tools:
                    raise ValueError(f"Unknown tool in step {step_num}: {call['tool']}")

            normalized_plan[step_num] = calls
        return normalized_plan


    async def plan_and_execute(self, query: str, reasoning_include: bool, ws: WebSocket, message: List[HistoryMessage] = []) -> Dict[int, List[Any]]:
        plan_output = self.planner(query=query)
        print(plan_output)
        tool_plan = self._validate_plan(plan_output.tool_plan)        
        results: Dict[int, List[Any]] = {}
        for step in sorted(tool_plan.keys()):
            calls = tool_plan[step]
            results[step] = self._execute_parallel(calls)
        prompt = f"""
            You are a friendly cybersecurity advisor. A threat was scanned and produced the following results:
            
            RESULT : {json.dumps(results, indent=2)}

            Explain these results in a clear, engaging, and friendly way using emojis:
            - Start with a cheerful intro (do NOT say "The numbers mean").
            - Highlight what is safe ✅, suspicious ⚠️, or dangerous ❌.
            - Give a concise verdict in plain language.
            - Provide 3–5 actionable tips for the user.
            - Make it concise, approachable, and easy to read, like a helpful guide.

            Example style:
            🚀 Scan Summary:
            - ✅ Mostly safe
            - ⚠️ Some caution
            - ❌ Dangerous

            🧐 Why it matters:
            ...

            💡 What you should do:
            1. ...
            2. ...

            This is the query : {query}
            """
        message.append({"role": "user", "content": prompt})
        result = await stream_response_contextual_respond(ws, reasoning_include, self.detection_groq_client, message, os.getenv("NORMAL_CHAT_MODEL"))
        return result

    def _execute_parallel(self, calls: List[Dict[str, Any]]) -> List[Any]:
        """
        Execute all calls in parallel, preserving input order
        """
        def run(call):
            tool = self.tools.get(call['tool'])
            func_name = call['function'].split(":")[0].strip()
            func = getattr(tool, func_name, None)
            if func is None:
                return {"error": f"Unknown function {call['function']} on {call['tool']}"}
            try:
                return func(**call['params'])
            except Exception as e:
                return {"error": str(e), "tool": call['tool'], "function": call['function']}

        results = [None] * len(calls)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_index = {executor.submit(run, call): i for i, call in enumerate(calls)}
            for future in concurrent.futures.as_completed(future_to_index):
                idx = future_to_index[future]
                results[idx] = future.result()
        return results
    
    async def detect_file(self,query: str, fileUrl : str, reasoning_include: bool,  ws: WebSocket, message: List[HistoryMessage] = []):
        stats = self.tools['DetectionTool'].detect_file(fileUrl)    
        prompt = f"""
            You are a friendly cybersecurity advisor. A threat was scanned and produced the following results:
            
            RESULT : {json.dumps(stats, indent=2)}

            Explain these results in a clear, engaging, and friendly way using emojis:
            - Start with a cheerful intro (do NOT say "The numbers mean").
            - Highlight what is safe ✅, suspicious ⚠️, or dangerous ❌.
            - Give a concise verdict in plain language.
            - Provide 3–5 actionable tips for the user.
            - Make it concise, approachable, and easy to read, like a helpful guide.

            Example style:
            🚀 Scan Summary:
            - ✅ Mostly safe
            - ⚠️ Some caution
            - ❌ Dangerous

            🧐 Why it matters:
            ...

            💡 What you should do:
            1. ...
            2. ...

            This is the query : {query}
            """
        print("*"*40)
        print("Detection file run")
        print("*"*40)
        print(prompt)
        print("*"*40)
        message.append({"role": "user", "content": prompt})
        result = await stream_response_contextual_respond(ws, reasoning_include, self.detection_groq_client, message, os.getenv("NORMAL_CHAT_MODEL"))
        return result
