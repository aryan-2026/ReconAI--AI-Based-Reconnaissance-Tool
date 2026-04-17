"""
ReconAI - Model Router
Supports: OpenAI, Claude (Anthropic), Gemini, Local LLM (Ollama)
"""
import os
import json
from typing import Optional
from core.config import LLM_PROVIDERS
from utils.logger import log


class ModelRouter:
    """Routes AI requests to the selected LLM provider."""

    def __init__(self, provider_id: str):
        self.provider_id = provider_id
        self.provider = LLM_PROVIDERS.get(provider_id)
        if not self.provider:
            raise ValueError(f"Unknown provider ID: {provider_id}")
        self.name  = self.provider["name"]
        self.model = self.provider["model"]
        self._client = None
        self._gemini_sdk = None   # "new" | "legacy"
        self._init_client()

    def _init_client(self):
        pid = self.provider_id

        if pid == "1":  # OpenAI
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise EnvironmentError("OPENAI_API_KEY not set in .env")
            self._client = OpenAI(api_key=api_key)

        elif pid == "2":  # Claude
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise EnvironmentError("ANTHROPIC_API_KEY not set in .env")
            self._client = anthropic.Anthropic(api_key=api_key)

        elif pid == "3":  # Gemini
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise EnvironmentError("GEMINI_API_KEY not set in .env")
            # Try new google-genai SDK first (recommended by Google as of 2025)
            try:
                from google import genai as new_genai
                self._client = new_genai.Client(api_key=api_key)
                self._gemini_sdk = "new"
                log.info("[ModelRouter] Using google-genai SDK (new)")
            except ImportError:
                # Fall back to legacy google-generativeai
                try:
                    import google.generativeai as legacy_genai
                    legacy_genai.configure(api_key=api_key)
                    self._client = legacy_genai.GenerativeModel(self.model)
                    self._gemini_sdk = "legacy"
                    log.info("[ModelRouter] Using google-generativeai SDK (legacy)")
                except ImportError:
                    raise EnvironmentError(
                        "No Gemini SDK found. Run: pip install google-genai"
                    )

        elif pid == "4":  # Ollama (Local)
            import ollama
            self._client = ollama

        log.info(f"[ModelRouter] Initialized provider: {self.name} | Model: {self.model}")

    def _get_gemini_model(self) -> str:
        """Return the correct Gemini model name for the active SDK."""
        if self._gemini_sdk == "new":
            # New SDK uses shorter model IDs
            model_map = {
                "gemini-1.5-pro":   "gemini-2.0-flash",
                "gemini-1.5-flash": "gemini-2.0-flash",
                "gemini-pro":       "gemini-2.0-flash",
            }
            return model_map.get(self.model, self.model)
        return self.model

    def query(self, prompt: str, system: Optional[str] = None, json_mode: bool = False) -> str:
        """
        Send a prompt to the selected LLM and return text response.
        Handles all provider differences transparently.
        """
        pid = self.provider_id
        sys_msg = system or (
            "You are ReconAI, an expert cybersecurity reconnaissance AI assistant. "
            "You analyze recon data and provide structured, actionable insights for bug bounty hunting."
        )

        try:
            if pid == "1":  # OpenAI
                kwargs = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": sys_msg},
                        {"role": "user",   "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 4096
                }
                if json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = self._client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content

            elif pid == "2":  # Claude
                resp = self._client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=sys_msg,
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.content[0].text

            elif pid == "3":  # Gemini
                model_id = self._get_gemini_model()
                full_prompt = f"{sys_msg}\n\n{prompt}"

                if self._gemini_sdk == "new":
                    resp = self._client.models.generate_content(
                        model=model_id,
                        contents=full_prompt
                    )
                    return resp.text
                else:
                    # Legacy SDK
                    resp = self._client.generate_content(full_prompt)
                    return resp.text

            elif pid == "4":  # Ollama
                resp = self._client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": sys_msg},
                        {"role": "user",   "content": prompt}
                    ]
                )
                return resp["message"]["content"]

        except Exception as e:
            log.error(f"[ModelRouter] LLM query failed ({self.name}): {e}")
            return f"ERROR: LLM query failed - {str(e)}"

    def analyze_recon_data(self, data: dict) -> dict:
        """Ask the LLM to analyze collected recon data and produce insights."""
        prompt = f"""
Analyze the following reconnaissance data collected for a bug bounty target.

Recon Data:
{json.dumps(data, indent=2)}

Your tasks:
1. Identify the highest-value targets for vulnerability testing
2. Highlight any exposed sensitive services or technologies
3. Flag potential vulnerability indicators from the data
4. Suggest next steps for vulnerability discovery
5. Score each high-priority target from 1-10

Return ONLY valid JSON in this exact format:
{{
  "analysis_summary": "...",
  "high_priority_targets": [
    {{"target": "...", "reason": "...", "score": 8, "suggested_tests": [...]}}
  ],
  "vulnerability_hints": [
    {{"target": "...", "hint_type": "...", "reason": "...", "priority": "HIGH|MEDIUM|LOW"}}
  ],
  "next_steps": ["..."],
  "risk_summary": "..."
}}
"""
        raw = self.query(prompt, json_mode=True)
        try:
            clean = raw.strip()
            # Strip markdown fences if present
            if clean.startswith("```"):
                parts = clean.split("```")
                # parts[1] is the content block
                clean = parts[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            return json.loads(clean.strip())
        except Exception as e:
            log.error(f"[ModelRouter] Failed to parse AI analysis: {e}")
            return {"error": str(e), "raw": raw}

    def classify_screenshot(self, url: str, title: str, tech: str) -> str:
        """Classify a web service based on its metadata."""
        prompt = f"""
Classify this web service for a bug bounty recon:
URL: {url}
Page Title: {title}
Detected Technologies: {tech}

Classify as ONE of: login_panel | admin_dashboard | monitoring_system | internal_tool | api_service | dev_environment | file_upload | unknown

Reply with ONLY the classification label.
"""
        return self.query(prompt).strip().lower().replace(" ", "_")
