from fastapi import FastAPI, Request, Response
import httpx

app = FastAPI(title="GateShield Gateway")

PROTECTED_API_BASE = "http://127.0.0.1:8001"


@app.get("/health")
def health():
    return {"status": "ok", "service": "gateway"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    target_url = f"{PROTECTED_API_BASE}/{path}"

    body = await request.body()

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient() as client:
        upstream_response = await client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            content=body,
            headers=headers,
        )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=dict(upstream_response.headers),
        media_type=upstream_response.headers.get("content-type"),
    )