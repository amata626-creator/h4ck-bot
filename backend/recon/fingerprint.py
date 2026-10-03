"""
Fingerprint the tech stack from headers, cookies, and response shape.

Not exhaustive; the goal is to give the semantic-model LLM enough
context to reason ("this is a Django app" changes what hypotheses are
plausible). A full Wappalyzer-style product is out of scope.
"""

from __future__ import annotations

import re

from recon.types import AuthHints, HttpTrace, TechStack

_FRAMEWORK_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    # (pattern matched against the lowercase server + powered-by + a
    # representative response body, product, language)
    (re.compile(r"express"),            "express",  "javascript"),
    (re.compile(r"next\.js|nextjs"),    "nextjs",   "javascript"),
    (re.compile(r"django"),             "django",   "python"),
    (re.compile(r"flask"),              "flask",    "python"),
    (re.compile(r"fastapi"),            "fastapi",  "python"),
    (re.compile(r"spring|springboot"),  "spring",   "java"),
    (re.compile(r"tomcat|coyote"),      "tomcat",   "java"),
    (re.compile(r"laravel"),            "laravel",  "php"),
    (re.compile(r"rails|puma|passenger"),"rails",   "ruby"),
    (re.compile(r"asp\.net|iis"),       "aspnet",   "csharp"),
    (re.compile(r"gunicorn|uvicorn"),   "python-wsgi", "python"),
    (re.compile(r"phusion passenger"),  "passenger", "ruby"),
]

_CMS_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"wp-content|wordpress"),  "wordpress"),
    (re.compile(r"drupal"),                "drupal"),
    (re.compile(r"joomla"),                "joomla"),
    (re.compile(r"magento"),               "magento"),
    (re.compile(r"shopify"),               "shopify"),
    (re.compile(r"ghost"),                 "ghost"),
]

_AUTH_HEADER_NAMES = {"authorization", "x-auth-token", "x-api-key", "x-access-token"}
_CSRF_PARAM_HINTS = {"csrf", "csrftoken", "csrf_token", "_token", "authenticity_token"}


def fingerprint(traces: list[HttpTrace]) -> TechStack:
    """Combine header- and body-based signals across all traces."""
    server = ""
    powered_by = ""
    detected: list[str] = []

    combined_lower = ""
    cookies: set[str] = set()
    auth_headers: set[str] = set()
    csrf_params: set[str] = set()

    for t in traces:
        h = {k.lower(): v for k, v in t.response_headers.items()}
        if not server and h.get("server"):
            server = h["server"]
        if not powered_by and h.get("x-powered-by"):
            powered_by = h["x-powered-by"]
        combined_lower += " " + t.response_body[:5000].lower()
        if h.get("set-cookie"):
            cookie_header = h["set-cookie"]
            for c in cookie_header.split(","):
                name = c.split("=", 1)[0].strip()
                if name:
                    cookies.add(name)
        for name in _AUTH_HEADER_NAMES:
            if name in h:
                auth_headers.add(name)

    combined = (server + " " + powered_by + " " + combined_lower).lower()

    framework = ""
    language = ""
    for pat, product, lang in _FRAMEWORK_SIGNATURES:
        if pat.search(combined):
            framework = product
            language = lang
            detected.append(product)
            break

    cms = ""
    for pat, product in _CMS_SIGNATURES:
        if pat.search(combined):
            cms = product
            detected.append(product)
            break

    return TechStack(
        server=server,
        powered_by=powered_by,
        framework=framework,
        language=language,
        cms=cms,
        detected_products=detected,
    )


def infer_auth_hints(traces: list[HttpTrace]) -> AuthHints:
    login_paths: list[str] = []
    cookie_names: set[str] = set()
    auth_headers: set[str] = set()
    csrf: set[str] = set()

    for t in traces:
        path = t.url.lower()
        body_lower = t.response_body.lower()
        if any(k in path for k in ("login", "signin", "auth", "session")):
            login_paths.append(t.url)
        if "password" in body_lower and "form" in body_lower:
            from urllib.parse import urlparse
            p = urlparse(t.url).path
            if p not in login_paths:
                login_paths.append(p)

        for k, v in t.response_headers.items():
            if k.lower() == "set-cookie":
                for c in v.split(","):
                    name = c.split("=", 1)[0].strip()
                    if name:
                        cookie_names.add(name)
            if k.lower() in _AUTH_HEADER_NAMES:
                auth_headers.add(k.lower())

        for hint in _CSRF_PARAM_HINTS:
            if hint in body_lower:
                csrf.add(hint)

    return AuthHints(
        login_paths=sorted(set(login_paths))[:10],
        cookie_names=sorted(cookie_names),
        auth_header_names=sorted(auth_headers),
        csrf_param_names=sorted(csrf),
    )
