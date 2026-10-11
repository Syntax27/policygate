"""A deliberately simple in-memory service, intended for local use only."""

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    title: str = Field(min_length=1, max_length=200)

    @field_validator("title")
    @classmethod
    def trim_title(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("title must not be blank")
        return value


def create_app() -> FastAPI:
    app = FastAPI(title="PolicyGate local demo service", docs_url=None, redoc_url=None, openapi_url=None)
    reports = [{"id": 1, "title": "Synthetic access review"}]

    @app.get("/reports")
    async def list_reports() -> dict:
        return {"reports": reports}

    @app.post("/reports", status_code=201)
    async def add_report(report: ReportInput) -> dict:
        item = {"id": len(reports) + 1, "title": report.title}
        reports.append(item)
        return item

    return app


app = create_app()
