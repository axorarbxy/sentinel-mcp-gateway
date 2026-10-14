import asyncio
import json
from types import SimpleNamespace

from starlette.requests import Request

import gateway
from modules.utility.password_analyzer import PasswordAnalyzer


def test_password_assessment_reports_per_password_scores():
    analyzer = PasswordAnalyzer()

    assessment = analyzer.assess_password("N7$vQ2!mL9#xR4@p")

    assert assessment["strength_score"] > 0.7
    assert assessment["risk_score"] == 1 - assessment["strength_score"]
    assert assessment["strength"] == "Strong"
    assert assessment["severity"] == "LOW"
    assert assessment["entropy"] > 0
    assert "password" not in assessment


def test_weak_password_assessment_returns_issues_without_plaintext():
    analyzer = PasswordAnalyzer()
    password = "password123"

    assessment = analyzer.assess_password(password)

    assert assessment["is_weak"] is True
    assert assessment["risk_score"] > 0.4
    assert assessment["issues"]
    event = analyzer.analyze(password)
    assert event is not None
    assert password not in str(event.to_dict())


def test_password_endpoint_returns_the_submitted_password_assessment(monkeypatch):
    analyzer = PasswordAnalyzer()
    monkeypatch.setattr(gateway, "cybereye", SimpleNamespace(
        analyze=lambda _kind, _value: [],
        get_risk_score=lambda: 0.26,
        modules={"PasswordAnalyzer": analyzer},
    ))
    password = "N7$vQ2!mL9#xR4@p"

    async def invoke_endpoint():
        request_body = json.dumps({"type": "password", "data": password}).encode()
        received = False

        async def receive():
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": request_body, "more_body": False}

        request = Request({
            "type": "http",
            "method": "POST",
            "path": "/cybereye/analyze",
            "headers": [(b"content-type", b"application/json")],
            "query_string": b"",
        }, receive)
        return await gateway.cybereye_analyze(request)

    body = asyncio.run(invoke_endpoint())
    assessment = analyzer.assess_password(password)
    assert body["risk_score"] == assessment["risk_score"]
    assert body["analysis"]["strength_score"] == assessment["strength_score"]
    assert password not in json.dumps(body)
