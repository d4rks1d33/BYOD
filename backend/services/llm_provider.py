"""
Multi-provider LLM abstraction layer.
Supports: Gemini, OpenAI, Anthropic, Ollama, vLLM, local .gguf models
"""
from __future__ import annotations
import json
import logging
import os
import time
from typing import Optional, List, Dict, Any, Literal
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


def _scan_log(level: str, agent: str, message: str) -> None:
    """Emit a log to the active scan logger (if any)."""
    try:
        from services.scan_logger import ScanLogger
        sl = ScanLogger.get_current()
        if sl:
            sl.log(level, agent, message)
    except Exception:
        pass


def _scan_log_llm_request(agent: str, model: str, messages: list, tools: Optional[list] = None) -> None:
    try:
        from services.scan_logger import ScanLogger
        sl = ScanLogger.get_current()
        if sl:
            sl.llm_request(agent, model, messages, tools)
    except Exception:
        pass


def _scan_log_llm_response(agent: str, model: str, content: str, tool_calls: Optional[list] = None) -> None:
    try:
        from services.scan_logger import ScanLogger
        sl = ScanLogger.get_current()
        if sl:
            sl.llm_response(agent, model, content, tool_calls)
    except Exception:
        pass


class LLMProvider(ABC):
    """Base class for LLM providers"""

    def __init__(self, model_name: str, **kwargs):
        self.model_name = model_name
        self.kwargs = kwargs
        self.agent_name = kwargs.get("agent_name", "LLM")

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        """
        Send chat request to LLM.
        Returns: {
            "content": str,
            "tool_calls": [{"name": str, "arguments": dict}] or None,
            "finish_reason": str
        }
        """
        pass


class GeminiProvider(LLMProvider):
    """Google Gemini provider"""

    def __init__(self, model_name: str = "gemini-2.5-flash", api_key: Optional[str] = None):
        super().__init__(model_name)
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not set")

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        start_time = time.time()
        agent = self.kwargs.get("agent_name", "GEMINI")

        # Log request
        _scan_log_llm_request(agent, self.model_name, messages, tools)

        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)

            # Extract system instruction (Gemini supports it now)
            system_instruction = None
            for msg in messages:
                if msg["role"] == "system":
                    system_instruction = msg["content"]
                    break

            model = genai.GenerativeModel(
                model_name=self.model_name,
                tools=self._convert_tools_to_gemini(tools) if tools else None,
                system_instruction=system_instruction,
            )

            # Convert messages to Gemini format (excluding system)
            non_system = [m for m in messages if m["role"] != "system"]

            # --- AVOID RATE LIMITS ---
            _scan_log("INFO", agent, "Waiting 15 seconds to avoid Rate Limits from Gemini Free Tier...")
            time.sleep(15)
            # -------------------------------------

            # Send the conversation
            if len(non_system) == 1:
                # Single message - just generate
                response = model.generate_content(
                    non_system[0]["content"],
                    generation_config=genai.GenerationConfig(
                        temperature=temperature,
                        max_output_tokens=max_tokens,
                    )
                )
            else:
                # Multi-turn - use chat
                chat = model.start_chat(history=self._convert_messages(non_system[:-1]))
                response = chat.send_message(
                    non_system[-1]["content"],
                    generation_config=genai.GenerationConfig(
                        temperature=temperature,
                        max_output_tokens=max_tokens,
                    )
                )

            # Parse response
            result = {
                "content": "",
                "tool_calls": [],
                "finish_reason": "stop"
            }

            if response.candidates and response.candidates[0].content.parts:
                for part in response.candidates[0].content.parts:
                    try:
                        if hasattr(part, 'text') and part.text:
                            result["content"] += part.text
                    except (AttributeError, ValueError):
                        pass
                    try:
                        if hasattr(part, 'function_call') and part.function_call and part.function_call.name:
                            result["tool_calls"].append({
                                "name": part.function_call.name,
                                "arguments": self._proto_to_dict(part.function_call.args) if part.function_call.args else {}
                            })
                    except (AttributeError, ValueError):
                        pass

            elapsed_ms = int((time.time() - start_time) * 1000)
            _scan_log_llm_response(agent, self.model_name, result["content"], result["tool_calls"])
            _scan_log("DEBUG", agent, f"Gemini call completed in {elapsed_ms}ms")

            return result

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            _scan_log("ERROR", agent, f"Gemini error after {elapsed_ms}ms: {e}")
            logger.error(f"Gemini API error: {e}", exc_info=True)
            raise

    def _convert_messages(self, messages: List[Dict[str, str]]) -> List:
        history = []
        for msg in messages:
            if msg["role"] == "system":
                continue  # System goes into system_instruction
            role = "user" if msg["role"] == "user" else "model"
            history.append({"role": role, "parts": [msg["content"]]})
        return history

    def _proto_to_dict(self, obj):
        """
        Recursively convert Gemini proto objects (MapComposite, RepeatedComposite)
        to native Python dicts/lists/primitives.
        """
        if obj is None:
            return None

        # Try MapComposite (dict-like)
        if hasattr(obj, 'items') and callable(obj.items):
            try:
                return {k: self._proto_to_dict(v) for k, v in obj.items()}
            except Exception:
                pass

        # Try RepeatedComposite / lists
        if hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, dict)):
            try:
                return [self._proto_to_dict(item) for item in obj]
            except Exception:
                pass

        # Try dict()
        if isinstance(obj, dict):
            return {k: self._proto_to_dict(v) for k, v in obj.items()}

        # Primitive types
        if isinstance(obj, (str, int, float, bool)):
            return obj

        # Last resort - convert to string
        try:
            return dict(obj)
        except Exception:
            try:
                return str(obj)
            except Exception:
                return None

    def _convert_tools_to_gemini(self, tools: List[Dict[str, Any]]) -> List:
        """
        Convert OpenAI-style tool definitions to Gemini format.
        Gemini expects type as UPPERCASE enum (STRING, OBJECT, INTEGER, etc.)
        """
        import google.generativeai as genai

        def normalize_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
            """Recursively normalize JSON Schema for Gemini."""
            if not isinstance(schema, dict):
                return schema

            type_map = {
                "string": "STRING",
                "integer": "INTEGER",
                "number": "NUMBER",
                "boolean": "BOOLEAN",
                "array": "ARRAY",
                "object": "OBJECT",
            }

            result = {}
            for key, value in schema.items():
                if key == "type" and isinstance(value, str):
                    result["type_"] = type_map.get(value.lower(), value.upper())
                elif key == "properties" and isinstance(value, dict):
                    result["properties"] = {k: normalize_schema(v) for k, v in value.items()}
                elif key == "items" and isinstance(value, dict):
                    result["items"] = normalize_schema(value)
                elif key == "default":
                    # Gemini doesn't support default
                    continue
                elif key == "format":
                    # Gemini has limited format support
                    if value in ("enum", "date-time"):
                        result[key] = value
                else:
                    result[key] = value
            return result

        gemini_tools = []
        for tool in tools:
            params = tool.get("parameters", {"type": "object", "properties": {}})
            normalized_params = normalize_schema(params)

            try:
                func_decl = genai.protos.FunctionDeclaration(
                    name=tool["name"],
                    description=tool["description"],
                    parameters=normalized_params,
                )
                gemini_tools.append(genai.protos.Tool(function_declarations=[func_decl]))
            except Exception as e:
                # Skip tools that fail conversion
                import logging
                logging.getLogger(__name__).warning(
                    f"Failed to convert tool {tool.get('name')} to Gemini: {e}"
                )
                continue

        return gemini_tools


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider"""

    def __init__(self, model_name: str = "gpt-4o", api_key: Optional[str] = None):
        super().__init__(model_name)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set")

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        start_time = time.time()
        agent = self.kwargs.get("agent_name", "OPENAI")
        _scan_log_llm_request(agent, self.model_name, messages, tools)

        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)

            kwargs = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            if tools:
                kwargs["tools"] = [
                    {
                        "type": "function",
                        "function": tool
                    }
                    for tool in tools
                ]

            response = client.chat.completions.create(**kwargs)

            message = response.choices[0].message
            result = {
                "content": message.content or "",
                "tool_calls": [],
                "finish_reason": response.choices[0].finish_reason
            }

            if message.tool_calls:
                for tc in message.tool_calls:
                    result["tool_calls"].append({
                        "name": tc.function.name,
                        "arguments": json.loads(tc.function.arguments)
                    })

            elapsed_ms = int((time.time() - start_time) * 1000)
            _scan_log_llm_response(agent, self.model_name, result["content"], result["tool_calls"])
            _scan_log("DEBUG", agent, f"OpenAI call completed in {elapsed_ms}ms")

            return result

        except Exception as e:
            _scan_log("ERROR", agent, f"OpenAI error: {e}")
            logger.error(f"OpenAI API error: {e}", exc_info=True)
            raise


class OpenRouterProvider(OpenAIProvider):
    """OpenRouter provider (OpenAI compatible)"""

    def __init__(self, model_name: str, api_key: Optional[str] = None):
        LLMProvider.__init__(self, model_name)
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set")

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        start_time = time.time()
        agent = self.kwargs.get("agent_name", "OPENROUTER")
        _scan_log_llm_request(agent, self.model_name, messages, tools)

        try:
            from openai import OpenAI
            # Aquí está la magia: usamos la librería de OpenAI pero apuntamos a OpenRouter
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key,
            )

            kwargs = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            if tools:
                kwargs["tools"] = [
                    {
                        "type": "function",
                        "function": tool
                    }
                    for tool in tools
                ]

            response = client.chat.completions.create(**kwargs)

            message = response.choices[0].message
            result = {
                "content": message.content or "",
                "tool_calls": [],
                "finish_reason": response.choices[0].finish_reason
            }

            if message.tool_calls:
                for tc in message.tool_calls:
                    result["tool_calls"].append({
                        "name": tc.function.name,
                        "arguments": json.loads(tc.function.arguments)
                    })

            elapsed_ms = int((time.time() - start_time) * 1000)
            _scan_log_llm_response(agent, self.model_name, result["content"], result["tool_calls"])
            _scan_log("DEBUG", agent, f"OpenRouter call completed in {elapsed_ms}ms")

            return result

        except Exception as e:
            _scan_log("ERROR", agent, f"OpenRouter error: {e}")
            logger.error(f"OpenRouter API error: {e}", exc_info=True)
            raise


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider"""

    def __init__(self, model_name: str = "claude-3-5-sonnet-20241022", api_key: Optional[str] = None):
        super().__init__(model_name)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        start_time = time.time()
        agent = self.kwargs.get("agent_name", "ANTHROPIC")
        _scan_log_llm_request(agent, self.model_name, messages, tools)

        try:
            from anthropic import Anthropic
            client = Anthropic(api_key=self.api_key)

            # Extract system message
            system = ""
            filtered_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system = msg["content"]
                else:
                    filtered_messages.append(msg)

            kwargs = {
                "model": self.model_name,
                "messages": filtered_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            if system:
                kwargs["system"] = system

            if tools:
                # Anthropic uses different schema - need to wrap in input_schema
                kwargs["tools"] = [
                    {
                        "name": tool["name"],
                        "description": tool["description"],
                        "input_schema": tool.get("parameters", {"type": "object", "properties": {}})
                    }
                    for tool in tools
                ]

            response = client.messages.create(**kwargs)

            result = {
                "content": "",
                "tool_calls": [],
                "finish_reason": response.stop_reason
            }

            for block in response.content:
                if block.type == "text":
                    result["content"] += block.text
                elif block.type == "tool_use":
                    result["tool_calls"].append({
                        "name": block.name,
                        "arguments": block.input
                    })

            elapsed_ms = int((time.time() - start_time) * 1000)
            _scan_log_llm_response(agent, self.model_name, result["content"], result["tool_calls"])
            _scan_log("DEBUG", agent, f"Anthropic call completed in {elapsed_ms}ms")

            return result

        except Exception as e:
            _scan_log("ERROR", agent, f"Anthropic error: {e}")
            logger.error(f"Anthropic API error: {e}", exc_info=True)
            raise


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider"""

    def __init__(self, model_name: str = "llama3.1:8b", host: str = "http://localhost:11434"):
        super().__init__(model_name)
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        start_time = time.time()
        agent = self.kwargs.get("agent_name", "OLLAMA")
        _scan_log_llm_request(agent, self.model_name, messages, tools)

        try:
            import requests

            # Ollama supports native tool calling in newer versions
            request_payload = {
                "model": self.model_name,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                }
            }

            # Try native tool calling first
            if tools:
                request_payload["tools"] = [
                    {"type": "function", "function": t} for t in tools
                ]

            response = requests.post(
                f"{self.host}/api/chat",
                json=request_payload,
                timeout=300,
            )
            response.raise_for_status()

            data = response.json()
            msg = data.get("message", {})

            result = {
                "content": msg.get("content", ""),
                "tool_calls": [],
                "finish_reason": "stop"
            }

            # Parse tool calls if returned
            for tc in msg.get("tool_calls", []):
                fn = tc.get("function", {})
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                result["tool_calls"].append({
                    "name": fn.get("name", ""),
                    "arguments": args,
                })

            elapsed_ms = int((time.time() - start_time) * 1000)
            _scan_log_llm_response(agent, self.model_name, result["content"], result["tool_calls"])
            _scan_log("DEBUG", agent, f"Ollama call completed in {elapsed_ms}ms")

            return result

        except Exception as e:
            _scan_log("ERROR", agent, f"Ollama error: {e}")
            logger.error(f"Ollama API error: {e}", exc_info=True)
            raise


class LlamaCppProvider(LLMProvider):
    """
    Local .gguf model via llama-cpp-python.
    Loads model from a file path; supports OpenAI-compatible interface.
    """

    _model_cache: Dict[str, Any] = {}

    def __init__(self, model_name: str = "local", gguf_path: Optional[str] = None, **kwargs):
        super().__init__(model_name, **kwargs)
        self.gguf_path = gguf_path or kwargs.get("gguf_path") or os.getenv("LOCAL_GGUF_PATH")
        if not self.gguf_path:
            raise ValueError("gguf_path required for LlamaCppProvider")
        if not os.path.exists(self.gguf_path):
            raise ValueError(f".gguf file not found: {self.gguf_path}")

    def _get_model(self):
        if self.gguf_path not in self._model_cache:
            from llama_cpp import Llama
            self._model_cache[self.gguf_path] = Llama(
                model_path=self.gguf_path,
                n_ctx=8192,
                n_gpu_layers=-1,  # Use GPU if available
                verbose=False,
            )
        return self._model_cache[self.gguf_path]

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        start_time = time.time()
        agent = self.kwargs.get("agent_name", "LLAMACPP")
        _scan_log_llm_request(agent, f"gguf:{os.path.basename(self.gguf_path)}", messages, tools)

        try:
            llm = self._get_model()

            # Append tool descriptions to system message (no native tools in llama-cpp)
            processed_messages = [dict(m) for m in messages]
            if tools:
                tool_desc = "\n\n# Available Tools (call by writing JSON):\n"
                for tool in tools:
                    tool_desc += f"- {tool['name']}: {tool['description']}\n"
                tool_desc += "\nTo invoke a tool, output JSON: {\"tool\": \"name\", \"args\": {...}}\n"

                for msg in processed_messages:
                    if msg["role"] == "system":
                        msg["content"] += tool_desc
                        break
                else:
                    processed_messages.insert(0, {"role": "system", "content": tool_desc})

            response = llm.create_chat_completion(
                messages=processed_messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            content = response["choices"][0]["message"].get("content", "") or ""

            # Try to parse tool calls from content
            tool_calls = []
            try:
                import re
                # Find JSON blocks
                json_pattern = r'\{[^{}]*"tool"[^{}]*"args"[^{}]*\{[^{}]*\}[^{}]*\}'
                for match in re.finditer(json_pattern, content):
                    try:
                        data = json.loads(match.group(0))
                        if "tool" in data and "args" in data:
                            tool_calls.append({"name": data["tool"], "arguments": data["args"]})
                    except Exception:
                        continue
            except Exception:
                pass

            result = {
                "content": content,
                "tool_calls": tool_calls,
                "finish_reason": "stop",
            }

            elapsed_ms = int((time.time() - start_time) * 1000)
            _scan_log_llm_response(agent, f"gguf:{os.path.basename(self.gguf_path)}", content, tool_calls)
            _scan_log("DEBUG", agent, f"LlamaCpp call completed in {elapsed_ms}ms")

            return result

        except Exception as e:
            _scan_log("ERROR", agent, f"LlamaCpp error: {e}")
            logger.error(f"LlamaCpp error: {e}", exc_info=True)
            raise


class VLLMProvider(LLMProvider):
    """vLLM local serving provider"""

    def __init__(self, model_name: str, base_url: str = "http://localhost:8000/v1"):
        super().__init__(model_name)
        self.base_url = base_url or os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1")

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        try:
            import requests

            response = requests.post(
                f"{self.base_url}/chat/completions",
                json={
                    "model": self.model_name,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
            )
            response.raise_for_status()

            data = response.json()
            message = data["choices"][0]["message"]

            return {
                "content": message.get("content", ""),
                "tool_calls": [],
                "finish_reason": data["choices"][0].get("finish_reason", "stop")
            }

        except Exception as e:
            logger.error(f"vLLM API error: {e}", exc_info=True)
            raise


# Factory function
def get_llm_provider(
    provider: Literal["gemini", "openai", "anthropic", "ollama", "vllm", "llamacpp"],
    model_name: Optional[str] = None,
    **kwargs
) -> LLMProvider:
    """Get LLM provider instance"""

    providers = {
        "gemini": GeminiProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
        "vllm": VLLMProvider,
        "llamacpp": LlamaCppProvider,
        "openai_compatible": OpenAIProvider,  # Alias
        "openrouter": OpenRouterProvider,
    }

    if provider not in providers:
        raise ValueError(f"Unknown provider: {provider}")

    if model_name:
        kwargs["model_name"] = model_name

    return providers[provider](**kwargs)
