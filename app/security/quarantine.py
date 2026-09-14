"""Safe Reversible Encrypted Quarantine Vault."""
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.config import QUARANTINE_DIR
from app.database.repository import Repository

XOR_KEY = 0x5A  # Reversible obfuscation key preventing PE header execution

class QuarantineVault:
    """Manages secure isolation, encryption, restoration, and deletion of threats."""

    def __init__(self, repository: Repository, vault_dir: Optional[Path] = None):
        self.repository = repository
        self.vault_dir = vault_dir or QUARANTINE_DIR
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def _xor_transform(self, src: str, dest: str) -> None:
        """Apply byte-level XOR obfuscation so Windows cannot execute the payload."""
        with open(src, "rb") as f_in, open(dest, "wb") as f_out:
            while chunk := f_in.read(65536):
                f_out.write(bytes([b ^ XOR_KEY for b in chunk]))

    def quarantine_file(self, file_path: str, reason: str, detection_source: str = "Scanner") -> Optional[int]:
        """Safely isolate and obfuscate an offending file."""
        if not os.path.isfile(file_path):
            return None

        file_name = os.path.basename(file_path)
        timestamp_prefix = int(time.time())
        quarantine_filename = f"{timestamp_prefix}_{file_name}.tlq"
        quarantine_path = str(self.vault_dir / quarantine_filename)

        try:
            # 1. Obfuscate into quarantine vault
            self._xor_transform(file_path, quarantine_path)
            # 2. Remove original file from active filesystem
            os.unlink(file_path)
            # 3. Log in database
            record_id = self.repository.add_quarantine_record(
                original_path=file_path,
                quarantine_path=quarantine_path,
                reason=reason,
                detection_source=detection_source,
            )
            return record_id
        except Exception:
            return None

    def restore_file(self, record_id: int) -> bool:
        """Restore an isolated file back to its original location."""
        records = [r for r in self.repository.get_quarantine_records() if r["id"] == record_id]
        if not records:
            return False

        rec = records[0]
        q_path = rec["quarantine_path"]
        orig_path = rec["original_path"]

        if not os.path.isfile(q_path):
            return False

        try:
            os.makedirs(os.path.dirname(orig_path), exist_ok=True)
            self._xor_transform(q_path, orig_path)
            os.unlink(q_path)
            self.repository.update_quarantine_status(record_id, "RESTORED")
            return True
        except Exception:
            return False

    def delete_permanently(self, record_id: int) -> bool:
        """Completely purge quarantined file from disk."""
        records = [r for r in self.repository.get_quarantine_records() if r["id"] == record_id]
        if not records:
            return False

        q_path = records[0]["quarantine_path"]
        try:
            if os.path.isfile(q_path):
                os.unlink(q_path)
            self.repository.update_quarantine_status(record_id, "DELETED")
            return True
        except Exception:
            return False

    def list_quarantined_items(self) -> List[Dict[str, Any]]:
        return self.repository.get_quarantine_records()
