
import os
import json
from contextlib import asynccontextmanager

import psycopg
from psycopg.types.json import Jsonb
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
MAX_BODY_SIZE = 1024 * 1024

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

CREATE_TABLE_SQL = """
                   CREATE TABLE IF NOT EXISTS callback_events (
                                                                  id BIGSERIAL PRIMARY KEY,
                                                                  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                       method TEXT NOT NULL,
                       path TEXT NOT NULL,
                       query_string TEXT,
                       client_ip TEXT,
                       headers JSONB NOT NULL,
                       payload JSONB,
                       raw_payload BYTEA NOT NULL,
                       content_type TEXT,
                       payload_size INTEGER NOT NULL
                       );

                   CREATE INDEX IF NOT EXISTS idx_callback_received_at
                       ON callback_events (received_at DESC); \
                   """


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with await psycopg.AsyncConnection.connect(
            DATABASE_URL
    ) as conn:
        await conn.execute(CREATE_TABLE_SQL)
        await conn.commit()

    yield


app = FastAPI(
    title="Callback Capture API",
    lifespan=lifespan
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/{context_path:path}")
async def capture_callback(request: Request, context_path: str):
    raw_body = bytearray()

    async for chunk in request.stream():
        if len(raw_body) + len(chunk) > MAX_BODY_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Payload too large"
            )
        raw_body.extend(chunk)

    body = bytes(raw_body)
    content_type = request.headers.get("content-type", "")

    headers = [
        {
            "name": name,
            "value": (
                "[REDACTED]"
                if name.lower() in SENSITIVE_HEADERS
                else value.decode("latin-1")
            ),
        }
        for key, value in request.scope["headers"]
        for name in [key.decode("latin-1")]
    ]

    payload = None

    if (
            "application/json" in content_type.lower()
            or "+json" in content_type.lower()
    ):
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            pass

    client_ip = (
        request.client.host
        if request.client
        else None
    )

    try:
        async with await psycopg.AsyncConnection.connect(
                DATABASE_URL
        ) as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO callback_events (
                        method,
                        path,
                        query_string,
                        client_ip,
                        headers,
                        payload,
                        raw_payload,
                        content_type,
                        payload_size
                    )
                    VALUES (
                               %s, %s, %s, %s, %s,
                               %s, %s, %s, %s
                           )
                        RETURNING id, received_at
                    """,
                    (
                        request.method,
                        request.url.path,
                        request.url.query,
                        client_ip,
                        Jsonb(headers),
                        Jsonb(payload),
                        body,
                        content_type,
                        len(body)
                    )
                )

                event_id, received_at = await cur.fetchone()

            await conn.commit()

    except psycopg.Error:
        return JSONResponse(
            status_code=503,
            content={
                "status": "storage_unavailable"
            }
        )

    return {
        "status": "accepted"
    }
