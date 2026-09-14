"""User Decision Memory to eliminate repeat alert fatigue."""
from typing import Optional
from app.database.repository import Repository

class UserDecisionMemory:
    """Remembers user choices ('Allow', 'Block') to prevent duplicate alerts."""

    def __init__(self, repository: Repository):
        self.repository = repository
        self._cached_decisions = {}

    def allow(self, target_identifier: str, reason: Optional[str] = "User clicked Allow") -> None:
        """Whitelist an executable, script, or path."""
        ident = target_identifier.strip().lower()
        self._cached_decisions[ident] = "ALLOW"
        self.repository.add_user_decision(ident, "ALLOW", reason)

    def block(self, target_identifier: str, reason: Optional[str] = "User clicked Block") -> None:
        ident = target_identifier.strip().lower()
        self._cached_decisions[ident] = "BLOCK"
        self.repository.add_user_decision(ident, "BLOCK", reason)

    def is_allowed(self, target_identifier: str) -> bool:
        """Check if an item is already approved."""
        ident = target_identifier.strip().lower()
        if ident in self._cached_decisions:
            return self._cached_decisions[ident] == "ALLOW"

        record = self.repository.get_user_decision(ident)
        if record:
            self._cached_decisions[ident] = record["decision"]
            return record["decision"] == "ALLOW"
        return False
