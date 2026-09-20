from recon.project_store import ProjectStore
from recon.project_traffic import ProgramTrafficStore


def test_program_reuses_identity_across_daily_sessions(tmp_path):
    db = tmp_path / "recon.db"
    project_root = tmp_path / "projects"

    # Patch the project root for this isolated test instance.
    import recon.project_store as module
    old_root = module.PROJECT_ROOT
    module.PROJECT_ROOT = project_root

    store = ProjectStore(db)
    try:
        program, day1 = store.ensure_session("Facebook", "2026-09-20")
        same_program, day2 = store.ensure_session("Facebook", "2026-09-21")

        assert program["id"] == same_program["id"]
        assert day1["id"] != day2["id"]
        assert day1["session_date"] != day2["session_date"]
        assert str(project_root / "2026-09-20" / "facebook") == day1["folder"]
        assert str(project_root / "2026-09-21" / "facebook") == day2["folder"]
    finally:
        store.close()
        module.PROJECT_ROOT = old_root


def test_program_traffic_isolated_between_programs(tmp_path):
    db = tmp_path / "recon.db"
    store = ProjectStore(db)
    traffic = ProgramTrafficStore(db)
    try:
        facebook, session = store.ensure_session("Facebook", "2026-09-20")
        other, other_session = store.ensure_session("Other Program", "2026-09-20")

        raw_request = (
            "GET /api/users?user_id=10 HTTP/1.1\r\n"
            "Host: target.test\r\n"
            "Accept: text/html\r\n\r\n"
        )
        raw_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<html><title>Users</title></html>"
        )

        traffic.observe(
            program_id=facebook["id"],
            session_id=session["id"],
            event={"message_id": "1", "request": raw_request, "response": raw_response},
        )

        assert traffic.hosts(facebook["id"])[0]["host"] == "target.test"
        assert traffic.hosts(other["id"]) == []

        finding_id = store.upsert_finding(
            program_id=facebook["id"],
            session_id=session["id"],
            agent="parameter-agent",
            host="target.test",
            category="missed_review",
            target="/api/users?user_id=10",
            title="Review user_id relationship",
            statement="user_id appears on a user resource",
            evidence=["GET /api/users?user_id=10"],
            confidence=0.52,
        )
        assert finding_id > 0
        before = store.list_findings("Facebook", host="target.test")
        assert before[0]["state"] == "needs_review"

        updated = store.update_finding_state(
            program="Facebook",
            finding_id=finding_id,
            state="not_interesting",
            operator_note="Already checked manually.",
        )
        assert updated["state"] == "not_interesting"
        assert updated["operator_note"] == "Already checked manually."

        learned = store.finding_learning_context(facebook["id"], "target.test")
        assert learned[0]["state"] == "not_interesting"
    finally:
        traffic.close()
        store.close()
