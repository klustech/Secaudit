from __future__ import annotations

import os
from pathlib import Path
from pydantic import BaseModel


class Settings(BaseModel):
    app_env: str = "development"
    app_port: int = 8000
    hf_token: str = ""
    hf_model_summary: str = "HuggingFaceTB/SmolLM3-3B"
    hf_model_classifier: str = "HuggingFaceTB/SmolLM3-3B"
    max_repo_mb: int = 40
    job_storage_path: Path = Path("./data/jobs")
    export_path: Path = Path("./data/exports")

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            app_env=os.getenv("APP_ENV", "development"),
            app_port=int(os.getenv("APP_PORT", "8000")),
            hf_token=os.getenv("HF_TOKEN", ""),
            hf_model_summary=os.getenv("HF_MODEL_SUMMARY", "HuggingFaceTB/SmolLM3-3B"),
            hf_model_classifier=os.getenv("HF_MODEL_CLASSIFIER", "HuggingFaceTB/SmolLM3-3B"),
            max_repo_mb=int(os.getenv("MAX_REPO_MB", "40")),
            job_storage_path=Path(os.getenv("JOB_STORAGE_PATH", "./data/jobs")),
            export_path=Path(os.getenv("EXPORT_PATH", "./data/exports")),
        )


settings = Settings.from_env()
