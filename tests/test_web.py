import pytest

from agent_identity.demo.estate import build_snapshot

PAGES = [
    "/",
    "/agents",
    "/data",
    "/data?show=all",
    "/identity",
    "/secrets",
    "/network",
    "/runtime",
    "/saas",
    "/findings",
    "/frameworks",
    "/scans",
]


@pytest.mark.parametrize("path", PAGES)
def test_page_renders(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert "Demo data" in response.text
    assert "Content-Security-Policy" in response.headers


def test_every_agent_store_and_identity_page_renders(client):
    snapshot = build_snapshot()
    for agent in snapshot.agents:
        assert client.get(f"/agents/{agent.id}").status_code == 200
    for store in snapshot.stores:
        assert client.get("/data/store", params={"arn": store.arn}).status_code == 200
    for identity in snapshot.identities:
        assert client.get("/identity/detail", params={"arn": identity.arn}).status_code == 200


def test_unknown_agent_is_404(client):
    assert client.get("/agents/nope").status_code == 404


def test_agents_filter_returns_partial_for_htmx(client):
    response = client.get("/agents?flag=admin", headers={"HX-Request": "true"})
    assert "ops-autopilot" in response.text
    assert "support-copilot" not in response.text
    assert "<html" not in response.text


def test_untrusted_host_is_rejected(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_cross_site_post_is_blocked(client):
    response = client.post("/scans/live", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


def test_live_view_without_scans_offers_a_scan(client):
    client.post("/view/live", follow_redirects=False)
    response = client.get("/")
    assert "Scan my account" in response.text
    assert "Demo data" not in response.text
