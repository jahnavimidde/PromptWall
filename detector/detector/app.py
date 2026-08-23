from __future__ import annotations

import asyncio
from bisect import bisect_left
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from .deterministic import detect_deterministic
from .gliner_layer import detect_gliner, load_model
from .merge import merge
from .semantic_injection import load_semantic_model, predict_injection


def _utf16_mapper(text: str):
    """Return a function mapping a Python codepoint offset to a UTF-16 code-unit
    offset. PromptWall runs in JS and slices the returned offsets as UTF-16
    (`text.slice`), so an astral-plane character (emoji, rare CJK > U+FFFF)
    before a span would otherwise misalign the mask. Identity for all-BMP text.
    """
    astral = [i for i, c in enumerate(text) if ord(c) > 0xFFFF]
    if not astral:
        return lambda pos: pos
    return lambda pos: pos + bisect_left(astral, pos)


class AnalyzeRequest(BaseModel):
    text: str
    phone_regions: list[str] | None = None
    entities: list[str] | None = None
    score_threshold: float = 0.0


class Entity(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float


class InjectionAnalyzeRequest(BaseModel):
    text: str


class InjectionAnalyzeResponse(BaseModel):
    score: float
    label: str
    intent: str


# Module-level reference so the background task is not garbage-collected
# before the lifespan generator is done (fixes RUF006).
_gliner_warmup_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global _gliner_warmup_task
    # Load the semantic model before serving so /health == ready (PromptWall polls it).
    await asyncio.to_thread(load_semantic_model)
    # Warm load GLiNER PII model concurrently in a background task.
    # The reference is kept at module level so it is not garbage-collected (RUF006).
    _gliner_warmup_task = asyncio.create_task(asyncio.to_thread(load_model))
    yield


app = FastAPI(title="PromptWall Detector", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=list[Entity])
def analyze(req: AnalyzeRequest) -> list[Entity]:
    deterministic = detect_deterministic(req.text, req.phone_regions)
    fuzzy = detect_gliner(req.text, req.score_threshold)
    spans = merge(deterministic, fuzzy, req.entities, 0.0)
    to_u16 = _utf16_mapper(req.text)
    return [
        Entity(
            entity_type=s.entity_type,
            start=to_u16(s.start),
            end=to_u16(s.end),
            score=round(s.score, 4),
        )
        for s in spans
    ]


@app.post("/analyze/injection", response_model=InjectionAnalyzeResponse)
def analyze_injection(req: InjectionAnalyzeRequest) -> InjectionAnalyzeResponse:
    try:
        res = predict_injection(req.text)
        return InjectionAnalyzeResponse(
            score=res["score"],
            label=res["label"],
            intent=res["intent"],
        )
    except Exception as err:
        from fastapi import HTTPException

        raise HTTPException(status_code=500, detail="Semantic injection analysis failed") from err
