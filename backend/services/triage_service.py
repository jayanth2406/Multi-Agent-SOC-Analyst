"""Service layer for selecting and validating the triage implementation."""

from backend.agents.triage import DeterministicTriageAgent, OptionalLLMTriageAdapter
from backend.config import Settings, get_settings
from backend.models.schemas import Alert, TriageResult


class TriageService:
    """Coordinate triage without putting business logic in the API route."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.rules_agent = DeterministicTriageAgent()
        self.llm_adapter = OptionalLLMTriageAdapter(
            api_key=self.settings.llm_api_key,
            model=self.settings.llm_model,
        )

    def triage(self, alert: Alert) -> TriageResult:
        """Return a schema-validated result, safely falling back to rules."""

        if self.settings.triage_mode == "llm" and self.settings.llm_api_key:
            try:
                return TriageResult.model_validate(self.llm_adapter.triage(alert))
            except Exception:
                pass
        return self.rules_agent.triage(alert)


triage_service = TriageService()
