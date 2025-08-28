import dspy
import concurrent.futures
from typing import Dict, List, Any

class PlannerAgent(dspy.Signature):
    """
    PlannerAgent analyzes a user query and produces a structured step-by-step tool execution plan.
    Each step maps to tools and their specific functions that should be executed in parallel.

    Inputs:
        query: The user question/query to analyze.

    Output:
        tool_plan: A dict mapping execution steps to tool calls.

        Notes:
        - Tools in the same step run in parallel.
        - Each tool call is a dict with "tool" (the tool name), "function" (the specific method), and "params" (a dict of parameters).
        - Available tools and their functions:
          - MITRE:
            - search_techniques: {"keyword": "..."}
            - get_mitigations_for_technique: {"technique_id": "..."}
            - get_mitigations_by_keyword: {"keyword": "..."}
            - get_techniques_for_mitigation: {"mitigation_id": "..."}
          - CVE:
            - search_cves: {"keyword": "..."}
            - get_cve_details: {"cve_id": "..."}
            - get_related_exploits: {"cve_id": "..."}
            - get_patch_info: {"cve_id": "..."}
          - SIEM:
            - search_logs: {"query": "..."}
            - get_alerts: {"severity": "..."} (severity can be "HIGH", "MEDIUM", "LOW")
            - get_event_details: {"event_id": "..."}
            - get_top_sources: {"n": integer}
            - get_summary: {} (no params)
            - correlate_with_ioc: {"ioc": "..."}
          - Threat Intelligence:
            - get_ip_reputation: {"ip": "..."}
            - get_domain_reputation: {"domain": "..."}
            - get_file_hash_reputation: {"hash": "..."}
            - get_active_threats: {} (no params)
          - MyanmarLaw:
            - ask: {"query": "..."}
          - Websearch:
            - websearch: {"query": "..."}
        - Params dict must match the required parameters for the function.
        - Steps are sequential; outputs from prior steps can inform later ones if needed, but the plan is generated upfront.
    """
    query: str = dspy.InputField(desc="The user query to plan against")
    tool_plan: dict = dspy.OutputField(
        desc=(
            "Structured execution plan. Keys = step numbers (integers starting from 1). "
            "Values = list of tool calls (each a dict with 'tool', 'function', 'params') to execute in parallel."
        )
    )

class ToolAgent:
    def __init__(self, tools: Dict[str, Any]):
        """
        Initialize the agent.
        - tools: Dict mapping tool names to their objects (e.g., {'MITRE': mitre_tool, 'CVE': cve_tool, ...}).
        """
        self.planner = dspy.ChainOfThought(PlannerAgent)
        self.tools = tools

    def _validate_plan(self, tool_plan: Dict) -> Dict[int, List[Dict[str, Any]]]:
        """
        Validate and normalize the tool plan. Convert string step keys to integers.
        """
        normalized_plan = {}
        for step, calls in tool_plan.items():
            try:
                step_num = int(step)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid step number: {step}")
            if step_num < 1:
                raise ValueError(f"Step number must be >= 1: {step_num}")
            if not isinstance(calls, list):
                raise ValueError(f"Tool calls for step {step_num} must be a list")
            for call in calls:
                if not all(k in call for k in ['tool', 'function', 'params']):
                    raise ValueError(f"Invalid tool call format in step {step_num}: {call}")
                if call['tool'] not in self.tools:
                    raise ValueError(f"Unknown tool in step {step_num}: {call['tool']}")
            normalized_plan[step_num] = calls
        return normalized_plan

    def plan_and_execute(self, query: str) -> Dict[int, List[Any]]:
        """
        Plan and execute based on the user query.
        Returns a dict where keys are steps, values are lists of results from tool calls in that step.
        """
        plan_output = self.planner(query=query)
        tool_plan = plan_output.tool_plan
        print(tool_plan)
        tool_plan = self._validate_plan(tool_plan)

        step_results: Dict[int, List[Any]] = {}
        for step in sorted(tool_plan.keys()):
            tool_calls = tool_plan[step]
            results = self._execute_parallel(tool_calls)
            step_results[step] = results

        return step_results

    def _execute_parallel(self, tool_calls: List[Dict[str, Any]]) -> List[Any]:
        """
        Execute a list of tool calls in parallel using ThreadPoolExecutor.
        Returns list of results in the order of tool_calls.
        """
        def execute_single(call: Dict[str, Any]) -> Any:
            tool_name = call['tool']
            func_name = call['function']
            params = call['params']
            try:
                if tool_name not in self.tools:
                    return f"Error: Unknown tool: {tool_name}"
                tool_obj = self.tools[tool_name]
                func = getattr(tool_obj, func_name, None)
                if func is None:
                    return f"Error: Unknown function {func_name} for tool {tool_name}"
                return func(**params)
            except Exception as e:
                return f"Error executing {tool_name}.{func_name}: {str(e)}"

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {executor.submit(execute_single, call): call for call in tool_calls}
            results = []
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
            
            ordered_results = [None] * len(tool_calls)
            
            for i, call in enumerate(tool_calls):
                for future in futures:
                    if futures[future] == call:
                        ordered_results[i] = future.result()
                        break
            return ordered_results

