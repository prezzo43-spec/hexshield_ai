"""Optional IP intelligence checks for high-risk authentication attempts."""

from __future__ import annotations

from typing import Any

import requests

from app.config import settings


def client_ip_from_request(request: Any) -> str:
    """Read the client address, trusting Render's forwarded header in production."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def assess_ip(ip_address: str) -> dict:
    """Return a normalized risk decision; disabled providers always allow."""
    if not settings.IP_RISK_API_KEY or ip_address in {"unknown", "127.0.0.1", "::1"}:
        return {"enabled": False, "blocked": False, "reason": "provider_disabled"}

    try:
        response = requests.get(
            f"https://ipqualityscore.com/api/json/ip/{settings.IP_RISK_API_KEY}/{ip_address}",
            params={"strictness": 1, "allow_public_access_points": True},
            timeout=3,
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return {"enabled": True, "blocked": False, "reason": "provider_unavailable"}

    reasons = []
    if settings.IP_RISK_BLOCK_VPN and data.get("vpn"):
        reasons.append("vpn")
    if settings.IP_RISK_BLOCK_PROXY and data.get("proxy"):
        reasons.append("proxy")
    if settings.IP_RISK_BLOCK_TOR and data.get("tor"):
        reasons.append("tor")
    if settings.IP_RISK_BLOCK_DATACENTER and data.get("is_crawler") is False and data.get("hosting"):
        reasons.append("datacenter")
    if int(data.get("fraud_score") or 0) >= settings.IP_RISK_MIN_FRAUD_SCORE:
        reasons.append("fraud_score")

    return {
        "enabled": True,
        "blocked": bool(reasons),
        "reason": ",".join(reasons) or "allowed",
        "country": data.get("country_code"),
        "organization": data.get("organization"),
        "vpn": bool(data.get("vpn")),
        "proxy": bool(data.get("proxy")),
        "tor": bool(data.get("tor")),
        "fraud_score": data.get("fraud_score"),
    }