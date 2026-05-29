# Agent Framework Support

The framework collector is a static source/config scanner. It helps bootstrap evidence; it does not prove deployed behavior.

## Target List

The list is ranked by public adoption signals, ecosystem visibility, and likelihood of appearing in enterprise agent reviews. It is not private usage telemetry.

| Rank | Framework | Current support |
| --- | --- | --- |
| 1 | LangChain / LangGraph | Python import and constructor scan for `create_agent`, `create_react_agent`, `AgentExecutor`, and `StateGraph`. |
| 2 | Microsoft AutoGen | Python scan for `AssistantAgent`, `ConversableAgent`, `UserProxyAgent`, `GroupChat`, and `RoutedAgent`. |
| 3 | LlamaIndex agents/workflows | Python scan for `FunctionAgent`, `ReActAgent`, `AgentWorkflow`, and `Workflow`. |
| 4 | CrewAI | Python scan for `Agent`, `Crew`, and `CrewBase`; basic `config/agents.yaml` extraction. |
| 5 | Agno | Python scan for `Agent`, `Team`, and `AgentOS` constructor tool lists. |
| 6 | Microsoft Semantic Kernel | Python scan for `Agent`, `ChatCompletionAgent`, `AzureAIAgent`, and `OpenAIAssistantAgent`. |
| 7 | OpenAI Agents SDK | Python scan for `Agent` and `SandboxAgent` from the `agents` package. |
| 8 | Google Agent Development Kit | Python scan for `Agent`, `LlmAgent`, `SequentialAgent`, `ParallelAgent`, and `LoopAgent`. |
| 9 | Haystack | Python scan for Haystack `Agent` and `Pipeline` references. |
| 10 | Pydantic AI | Python scan for `pydantic_ai.Agent` constructor tool lists. |

Additional first-pass recognition exists for Microsoft Agent Framework and CAMEL.

## Command

```bash
agentguard-graph collect --framework-code PATH --out agent-evidence/
```

`collect --project-dir` also enables the framework scan when known dependency files or CrewAI config files are present.

## What It Extracts

- supported framework imports
- visible agent ids or names from common constructors
- literal tool lists from keywords such as `tools`, `functions`, `toolsets`, and `mcp_servers`
- CrewAI `config/agents.yaml` agent entries
- an untrusted `agent_user_prompt` input source when agent wiring is found

Extracted tools become MCP-style static evidence so the existing graph and path rules can run.

## What It Does Not Extract

- dynamically generated tools
- decorators or factories that require execution
- remote MCP catalogs
- production IAM
- OAuth scopes
- approval rules
- data classifications
- runtime behavior

Add MCP descriptors, OpenAPI JSON, tool manifests, identity/admin exports, approval policy exports, and runtime events to raise confidence.
