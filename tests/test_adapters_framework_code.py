import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard_graph.adapters.framework_code import parse_framework_code


class FrameworkCodeCollectorTests(unittest.TestCase):
    def test_static_python_framework_parsing(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            examples = {
                "langgraph_agent.py": """
from langgraph.prebuilt import create_react_agent

graph = create_react_agent(model, tools=[search_docs, send_customer_email])
""",
                "autogen_agent.py": """
from autogen_agentchat.agents import AssistantAgent

assistant = AssistantAgent(name="AutoGen Reviewer", tools=[github_create_pr])
""",
                "llamaindex_agent.py": """
from llama_index.core.agent.workflow import FunctionAgent

agent = FunctionAgent(name="Llama Researcher", tools=[query_tool])
""",
                "crewai_agent.py": """
from crewai import Agent

researcher = Agent(role="Researcher", tools=[serper_search])
""",
                "agno_agent.py": """
from agno.agent import Agent

agent = Agent(name="Agno Ops", tools=[send_slack_message])
""",
                "semantic_kernel_agent.py": """
from semantic_kernel.agents import ChatCompletionAgent

agent = ChatCompletionAgent(name="SK Support", tools=[ticket_tool])
""",
                "microsoft_agent_framework.py": """
from agent_framework import Agent

agent = Agent(name="MAF Agent", tools=[deploy_release])
""",
                "openai_agent.py": """
from agents import Agent

agent = Agent(name="OpenAI Refunds", tools=[refund_customer])
""",
                "google_adk_agent.py": """
from google.adk.agents import Agent

root_agent = Agent(name="ADK Agent", tools=[web_search])
""",
                "haystack_agent.py": """
from haystack.components.agents import Agent

agent = Agent(tools=[knowledge_search])
""",
                "pydantic_ai_agent.py": """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5", tools=[weather_tool])
""",
                "camel_agent.py": """
from camel.agents import ChatAgent

agent = ChatAgent()
""",
            }
            for file_name, source in examples.items():
                (project / file_name).write_text(source, encoding="utf-8")

            parsed = parse_framework_code(project)

            framework_ids = {framework["id"] for framework in parsed["frameworks"]}
            self.assertTrue(
                {
                    "langchain_langgraph",
                    "autogen",
                    "llamaindex",
                    "crewai",
                    "agno",
                    "semantic_kernel",
                    "microsoft_agent_framework",
                    "openai_agents",
                    "google_adk",
                    "haystack",
                    "pydantic_ai",
                    "camel",
                }.issubset(framework_ids)
            )
            agent_ids = {agent["id"] for agent in parsed["agents"]}
            self.assertIn("autogen-reviewer", agent_ids)
            self.assertIn("openai-refunds", agent_ids)
            tool_names = {tool["name"] for tool in parsed["tools"]}
            self.assertIn("github_create_pr", tool_names)
            self.assertIn("refund_customer", tool_names)
            self.assertIn("send_customer_email", tool_names)
            self.assertTrue(parsed["input_sources"])
            self.assertTrue(any("static framework collector" in warning for warning in parsed["warnings"]))

    def test_crewai_yaml_parsing(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            config = project / "config"
            config.mkdir()
            (config / "agents.yaml").write_text(
                """
researcher:
  role: Market Researcher
  tools:
    - serper_search
    - scrape_website
writer:
  role: Report Writer
  tools: [write_report]
""",
                encoding="utf-8",
            )

            parsed = parse_framework_code(project)

            agents = {agent["id"]: agent for agent in parsed["agents"]}
            self.assertEqual(agents["researcher"]["name"], "Market Researcher")
            self.assertEqual(agents["writer"]["tools"], ["write_report"])
            tool_names = {tool["name"] for tool in parsed["tools"]}
            self.assertIn("serper_search", tool_names)
            self.assertIn("scrape_website", tool_names)


if __name__ == "__main__":
    unittest.main()
