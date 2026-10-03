"""
Read an OpenAPI 3.x or Swagger 2.x spec and extract endpoints.

Tries a fixed list of well-known locations first, then, if the site
references a spec in HTML (e.g. via <link rel="...">), respects that.

The extraction is deliberately shallow: path, methods, parameter names,
and a note about the response shape. The LLM consumes this alongside
the crawled endpoints and merges the picture.
"""

from __future__ import annotations

from typing import Optional

import httpx

from recon.types import Endpoint

SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/.well-known/openapi.json",
]

REQ_TIMEOUT = 6.0


async def find_and_parse(client: httpx.AsyncClient, base_url: str) -> tuple[Optional[dict], list[Endpoint]]:
    """
    Try known spec locations. On success, return the raw spec plus the
    endpoints extracted from it. On failure, return (None, []).
    """
    base = base_url.rstrip("/")
    for path in SPEC_PATHS:
        try:
            resp = await client.get(base + path)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        ctype = resp.headers.get("content-type", "").lower()
        if "json" not in ctype and "yaml" not in ctype and not resp.text.lstrip().startswith("{"):
            continue
        try:
            spec = resp.json()
        except Exception:
            continue
        endpoints = _extract_endpoints(spec)
        if endpoints:
            return spec, endpoints
    return None, []


def _extract_endpoints(spec: dict) -> list[Endpoint]:
    """Works for both OpenAPI 3.x (paths -> methods) and Swagger 2.x."""
    endpoints: list[Endpoint] = []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        methods = []
        params: list[str] = []
        sample_keys: list[str] = []

        for method in ("get", "post", "put", "delete", "patch", "options", "head"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            methods.append(method.upper())

            # parameters: could be at path level or operation level
            op_params = (path_item.get("parameters") or []) + (op.get("parameters") or [])
            for p in op_params:
                if isinstance(p, dict) and "name" in p:
                    params.append(str(p["name"]))

            # response shape: grab top-level keys from the 200 schema
            responses = op.get("responses", {})
            for code in ("200", "201", "default"):
                r = responses.get(code)
                if not isinstance(r, dict):
                    continue
                schema = (r.get("content", {})
                           .get("application/json", {})
                           .get("schema", {}))
                if isinstance(schema, dict):
                    props = schema.get("properties")
                    if isinstance(props, dict):
                        sample_keys = list(props.keys())[:20]
                        break

        if methods:
            # Dedup params
            seen = set()
            uniq_params = [p for p in params if not (p in seen or seen.add(p))]
            endpoints.append(Endpoint(
                path=path,
                methods=sorted(set(methods)),
                discovered_from="openapi",
                params=uniq_params,
                content_type="application/json",
                sample_response_keys=sample_keys,
            ))

    return endpoints
