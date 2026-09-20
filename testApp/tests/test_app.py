"""End-to-end tests drive authentication, tenant data, the web API, and every attack case."""

import secrets
from pathlib import Path

from fastapi.testclient import TestClient

from roadshield.attacks import CASES
from roadshield.auth import totp
from roadshield.config import AppSettings
from roadshield.main import create_app
from roadshield.store import AppStore

ORIGIN = "http://testserver"


def client(tmp_path):
    settings = AppSettings(
        database_url=f"sqlite:///{tmp_path / 'roadshield.db'}",
        secret=secrets.token_urlsafe(48),
        origin=ORIGIN,
        cookie_secure=False,
    )
    return TestClient(create_app(settings))


def login(
    browser: TestClient,
    *,
    tenant="roadshield-midwest",
    email="alice@roadshield.test",
    password="Demo-Alice-2026!",
):
    response = browser.post(
        "/api/auth/login",
        headers={"Origin": ORIGIN},
        json={"tenant_id": tenant, "email": email, "password": password},
    )
    assert response.status_code == 200
    assert browser.cookies.get("roadshield_session")
    assert browser.cookies.get("roadshield_csrf")
    return {"Origin": ORIGIN, "X-CSRF-Token": browser.cookies["roadshield_csrf"]}


def test_auth_dashboard_and_tenant_isolation(tmp_path):
    with client(tmp_path) as browser:
        assert browser.get("/api/dashboard").status_code == 401
        login(browser)
        dashboard = browser.get("/api/dashboard").json()
        assert dashboard["profile"]["display_name"] == "Alice Driver"
        assert [item["policy_number"] for item in dashboard["policies"]] == ["RS-MW-100001"]
        assert all(item["tenant_id"] == "roadshield-midwest" for item in dashboard["policies"])

        browser.post(
            "/api/auth/logout",
            headers={"Origin": ORIGIN, "X-CSRF-Token": browser.cookies["roadshield_csrf"]},
            json={},
        )
        login(browser, tenant="globex-insurance", email="bob@globex.test", password="Demo-Bob-2026!")
        other_dashboard = browser.get("/api/dashboard").json()
        assert [item["policy_number"] for item in other_dashboard["policies"]] == ["GX-W-900001"]
        assert "RS-MW-100001" not in str(other_dashboard)


def test_invalid_password_and_csrf_are_rejected(tmp_path):
    with client(tmp_path) as browser:
        bad = browser.post(
            "/api/auth/login",
            headers={"Origin": ORIGIN},
            json={
                "tenant_id": "roadshield-midwest",
                "email": "alice@roadshield.test",
                "password": "incorrect-password",
            },
        )
        assert bad.status_code == 401
        headers = login(browser)
        assert (
            browser.post("/api/chat", json={"message": "hello", "operation_id": "1" * 32}).status_code == 403
        )
        headers["X-CSRF-Token"] = "wrong-token"
        assert (
            browser.post(
                "/api/chat", headers=headers, json={"message": "hello", "operation_id": "2" * 32}
            ).status_code
            == 403
        )


def test_normal_chat_does_not_receive_dashboard_pii(tmp_path):
    with client(tmp_path) as browser:
        headers = login(browser)
        response = browser.post(
            "/api/chat",
            headers=headers,
            json={"message": "What does coverage include?", "operation_id": "3" * 32},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "OK"
        request = browser.app.state.agent_provider.last_request
        assert request is not None
        assert "100 Test Avenue" not in request.user
        assert "alice@roadshield.test" not in request.user
        assert "+1 312 555 0101" not in request.user
        assert "RoadShield Customer Care AI" in request.system
        assert "Retrieved documents" in request.system


def test_every_attack_scenario_meets_expected_boundary(tmp_path):
    with client(tmp_path) as browser:
        headers = login(browser)
        results = {}
        for name in CASES:
            response = browser.post(f"/api/attacks/{name}", headers=headers, json={})
            assert response.status_code == 200, (name, response.text)
            results[name] = response.json()
            assert results[name]["protected"] is True, results[name]
        assert results["direct-injection"]["actual"] == "BLOCKED"
        assert results["indirect-injection"]["actual"] == "BLOCKED"
        assert results["cross-tenant-tool"]["actual"] == "DENIED"
        assert "123-45-6789" not in results["pii-output"]["answer"]
        assert results["pii-output"]["answer"].count("[REDACTED]") == 2
        assert len(browser.get("/api/attacks/history").json()["runs"]) == len(CASES)


def test_body_limit_and_security_headers(tmp_path):
    with client(tmp_path) as browser:
        response = browser.get("/")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert "default-src 'self'" in response.headers["content-security-policy"]
        assert "object-src 'none'" in response.headers["content-security-policy"]
        oversized = browser.post(
            "/api/auth/login",
            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
            content=b"x" * 40000,
        )
        assert oversized.status_code == 413


def test_pdf_upload_is_tenant_scoped_and_poisoned_content_is_quarantined(tmp_path):
    attack_pdf = Path(__file__).parents[1] / "roadshield-claims-update-poisoned.pdf"
    with client(tmp_path) as browser:
        headers = login(browser)
        upload = browser.post(
            "/api/chat/upload",
            headers=headers,
            files={"file": (attack_pdf.name, attack_pdf.read_bytes(), "application/pdf")},
        )
        assert upload.status_code == 200, upload.text
        assert upload.json()["pages"] == 1

        blocked = browser.post(
            "/api/chat",
            headers=headers,
            json={
                "message": "Explain this attached bulletin",
                "operation_id": "4" * 32,
                "attachment_ids": [upload.json()["document_id"]],
            },
        )
        assert blocked.status_code == 200
        assert blocked.json()["status"] == "BLOCKED"
        assert blocked.json()["attachment_results"] == [
            {
                "document_id": upload.json()["document_id"],
                "status": "quarantined",
                "code": "POISONED_DOCUMENT",
            }
        ]

        browser.post(
            "/api/auth/logout",
            headers={"Origin": ORIGIN, "X-CSRF-Token": browser.cookies["roadshield_csrf"]},
            json={},
        )
        bob_headers = login(
            browser,
            tenant="globex-insurance",
            email="bob@globex.test",
            password="Demo-Bob-2026!",
        )
        isolated = browser.post(
            "/api/chat",
            headers=bob_headers,
            json={"message": "Explain bulletin RS-CLM-2026-09", "operation_id": "5" * 32},
        )
        assert isolated.status_code == 200
        assert isolated.json()["status"] == "OK"


def test_pdf_upload_rejects_active_content_and_wrong_media_type(tmp_path):
    with client(tmp_path) as browser:
        headers = login(browser)
        active = browser.post(
            "/api/chat/upload",
            headers=headers,
            files={"file": ("active.pdf", b"%PDF-1.4\n/JavaScript\n%%EOF", "application/pdf")},
        )
        assert active.status_code == 400
        assert active.json()["detail"] == "active PDF content is not allowed"
        text_upload = browser.post(
            "/api/chat/upload",
            headers=headers,
            files={"file": ("notes.txt", b"plain text", "text/plain")},
        )
        assert text_upload.status_code == 400
        assert text_upload.json()["detail"] == "only PDF files are accepted"


def test_agent_status_does_not_expose_credentials(tmp_path):
    with client(tmp_path) as browser:
        login(browser)
        response = browser.get("/api/agent/status")
        assert response.status_code == 200
        assert response.json() == {"provider": "Local deterministic simulator"}


def test_development_secret_and_login_survive_restart(tmp_path, monkeypatch):
    """A persistent database must not strand its password hashes after restart."""
    database = tmp_path / "persistent.db"
    secret_file = tmp_path / "development.secret"
    monkeypatch.setenv("TESTAPP_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("TESTAPP_SECRET_FILE", str(secret_file))
    monkeypatch.setenv("TESTAPP_ORIGIN", ORIGIN)
    monkeypatch.delenv("TESTAPP_SECRET", raising=False)

    first_settings = AppSettings.from_env()
    with TestClient(create_app(first_settings)) as browser:
        login(browser)

    second_settings = AppSettings.from_env()
    assert second_settings.secret == first_settings.secret
    with TestClient(create_app(second_settings)) as browser:
        login(browser)


def test_existing_lab_database_repairs_hash_after_secret_change(tmp_path):
    """Databases made with the former random secret remain usable."""
    database_url = f"sqlite:///{tmp_path / 'legacy.db'}"
    old = AppSettings(
        database_url=database_url,
        secret=secrets.token_urlsafe(48),
        origin=ORIGIN,
        cookie_secure=False,
    )
    with TestClient(create_app(old)) as browser:
        login(browser)

    replacement = AppSettings(
        database_url=database_url,
        secret=secrets.token_urlsafe(48),
        origin=ORIGIN,
        cookie_secure=False,
    )
    with TestClient(create_app(replacement)) as browser:
        login(browser)


def test_security_console_requires_dedicated_role_scope_and_mfa(tmp_path):
    with client(tmp_path) as browser:
        customer_headers = login(browser)
        assert browser.get("/api/security/overview").status_code == 403
        assert (
            browser.post("/api/attacks/direct-injection", headers=customer_headers, json={}).status_code
            == 200
        )
        browser.post("/api/auth/logout", headers=customer_headers, json={})

        missing_mfa = browser.post(
            "/api/auth/login",
            headers={"Origin": ORIGIN},
            json={
                "tenant_id": "roadshield-midwest",
                "email": "soc@roadshield.test",
                "password": "Demo-SOC-2026!",
            },
        )
        assert missing_mfa.status_code == 401
        authenticated = browser.post(
            "/api/auth/login",
            headers={"Origin": ORIGIN},
            json={
                "tenant_id": "roadshield-midwest",
                "email": "soc@roadshield.test",
                "password": "Demo-SOC-2026!",
                "mfa_code": totp("JBSWY3DPEHPK3PXP"),
            },
        )
        assert authenticated.status_code == 200
        overview = browser.get("/api/security/overview")
        assert overview.status_code == 200
        assert overview.json()["integrity"]["valid"] is True
        events = browser.get("/api/security/events?limit=10")
        assert events.status_code == 200
        assert events.json()["events"]
        assert "payload" not in str(events.json())
        high_event = next(event for event in events.json()["events"] if event["severity"] == "high")
        csrf_headers = {
            "Origin": ORIGIN,
            "X-CSRF-Token": browser.cookies["roadshield_csrf"],
        }
        acknowledged = browser.post(
            f"/api/security/events/{high_event['event_id']}/case",
            headers=csrf_headers,
            json={"state": "acknowledged", "case_id": "SOC-1001"},
        )
        assert acknowledged.status_code == 200
        detail = browser.get(f"/api/security/events/{high_event['event_id']}").json()
        assert detail["case"]["state"] == "acknowledged"
        assert detail["case"]["case_id"] == "SOC-1001"


def test_active_pdf_content_is_rejected_inside_the_parsed_object_graph():
    """The raw-byte prefilter cannot see into a compressed object stream.

    PDF 1.5 and later store most objects inside Flate-compressed streams, so a
    crafted file carries /OpenAction or /JavaScript straight past a byte scan.
    The object-graph walk is what actually enforces the rule, and it compares
    parsed PDF names, so a str/bytes mismatch there would silently allow
    everything while still looking like a working control.
    """
    from pypdf.generic import ArrayObject, DictionaryObject, NameObject, create_string_object

    from roadshield.documents import FORBIDDEN_PDF_NAMES, DocumentRejected, _reject_active_objects

    assert all(isinstance(name, str) and name.startswith("/") for name in FORBIDDEN_PDF_NAMES)

    nested = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Catalog"),
            NameObject("/Pages"): DictionaryObject(
                {
                    NameObject("/Kids"): ArrayObject(
                        [
                            DictionaryObject(
                                {
                                    NameObject("/AA"): DictionaryObject(
                                        {NameObject("/JS"): create_string_object("app.alert(1)")}
                                    )
                                }
                            )
                        ]
                    )
                }
            ),
        }
    )
    try:
        _reject_active_objects(nested)
        raise AssertionError("nested active content was accepted")
    except DocumentRejected:
        pass

    benign = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Catalog"),
            NameObject("/Pages"): DictionaryObject({NameObject("/Count"): create_string_object("1")}),
        }
    )
    _reject_active_objects(benign)

    # A self-referential graph must terminate rather than exhaust the stack.
    cyclic = DictionaryObject({NameObject("/Type"): NameObject("/Catalog")})
    cyclic[NameObject("/Self")] = cyclic
    _reject_active_objects(cyclic)


def test_failed_logins_are_counted_and_lock_out_both_source_and_account(tmp_path, monkeypatch):
    """A failed attempt must survive the transaction that rejected it.

    The counter previously shared the credential-check transaction, so the
    rollback on "invalid credentials" erased the increment and only successful
    logins were ever counted. Keying solely on the source address also left the
    account itself open to guesses spread across many addresses.
    """
    settings = AppSettings(
        database_url=f"sqlite:///{tmp_path / 'lockout.db'}",
        secret=secrets.token_urlsafe(48),
        origin=ORIGIN,
        cookie_secure=False,
    )
    store = AppStore(settings)
    store.initialize()
    store.seed_user(
        tenant_id="t",
        email="v@x.test",
        password="Correct-Horse-2026!",
        display_name="V",
        phone="1",
        address="a",
        role="customer",
        scopes={"chat:use"},
        conversation_id="0" * 32,
    )

    # The throttle buckets by wall-clock minute. Real attempts spread over a
    # rollover legitimately get a fresh allowance, but a test that straddles one
    # silently loses its counter and reports "never locked out". Freeze the clock
    # so the assertion is about the counter, not about when the test happened to
    # run. This flaked roughly one run in three before being pinned.
    import roadshield.store as store_module

    frozen = 1_800_000_000.0
    monkeypatch.setattr(store_module.time, "time", lambda: frozen)

    def attempts_until_locked(address):
        for index in range(60):
            try:
                store.login("t", "v@x.test", "wrong-password-guess", address(index))
            except PermissionError as exc:
                if "rate" in str(exc):
                    return index + 1
        return None

    single_source = attempts_until_locked(lambda _: "10.0.0.1")
    assert single_source is not None and single_source <= settings.login_attempts_per_minute + 1

    fresh = AppStore(
        AppSettings(
            database_url=f"sqlite:///{tmp_path / 'lockout2.db'}",
            secret=settings.secret,
            origin=ORIGIN,
            cookie_secure=False,
        )
    )
    fresh.initialize()
    fresh.seed_user(
        tenant_id="t",
        email="v@x.test",
        password="Correct-Horse-2026!",
        display_name="V",
        phone="1",
        address="a",
        role="customer",
        scopes={"chat:use"},
        conversation_id="0" * 32,
    )
    store.close()
    store = fresh
    distributed = attempts_until_locked(lambda i: f"10.0.{i // 255}.{i % 255}")
    assert distributed is not None, "guesses spread across addresses never locked the account"
    assert distributed <= settings.account_login_attempts_per_minute + 1
    store.close()
