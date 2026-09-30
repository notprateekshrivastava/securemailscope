from __future__ import annotations

import os
from pathlib import Path

from .version import ANALYZER_VERSION


class Settings:
    app_name: str = "SecureMailScope API"
    version: str = ANALYZER_VERSION
    data_dir: Path = Path(os.getenv("SECUREMAILSCOPE_DATA_DIR", "data"))
    model_dir: Path = Path(os.getenv("SECUREMAILSCOPE_MODEL_DIR", "models"))
    max_upload_mb: int = int(os.getenv("SECUREMAILSCOPE_MAX_UPLOAD_MB", "100"))
    # On Windows this can be an absolute path such as
    # C:\\Program Files\\Wireshark\\tshark.exe.
    tshark_path: str = os.getenv("SECUREMAILSCOPE_TSHARK_PATH", "")
    cors_origins: list[str] = [
        origin.strip()
        for origin in os.getenv(
            "SECUREMAILSCOPE_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"
        ).split(",")
        if origin.strip()
    ]

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def analysis_dir(self) -> Path:
        return self.data_dir / "analyses"

    def ensure_directories(self) -> None:
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
