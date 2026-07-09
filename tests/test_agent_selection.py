import sys, unittest
sys.argv = ["agent.py"]
import agent as A
import config as C


def _cfg(persona="공격Agent", max_persp=3):
    return C.Config(
        kestrel_token="t", kestrel_api="x", backend="dry", anthropic_api_key="",
        anthropic_model="m", ollama_host="h", ollama_model="m", persona=persona,
        persona_prompt="p", interval=1, use_feeds=False, feeds=(), topic_hours=0, digest_hours=0,
        openai_base_url="x", openai_api_key="", openai_model="m", llm_timeout=0,
        max_perspectives=max_persp, analysis_model="",
    )


class FakeState:
    def __init__(self):
        self.analyzed_cves = set()
        self.commented_analyses = set()
        self.replied_comments = set()
        self.commented_authors = {}
        self.memory = []
        self.last_topic_ts = 0.0
    def save(self): pass


def _agent(persona="공격Agent", max_persp=3):
    from brain import DryBrain
    cfg = _cfg(persona, max_persp)
    return A.Agent(cfg, object(), DryBrain(cfg), FakeState(), persona)


class TestSelection(unittest.TestCase):
    def test_analysis_counts(self):
        ag = _agent()
        community = [{"cveId": "CVE-1"}, {"cveId": "CVE-1"}, {"cveId": "CVE-2"}]
        counts = ag._analysis_counts(community)
        self.assertEqual(counts["CVE-1"], 2)
        self.assertEqual(counts["CVE-2"], 1)

    def test_perspective_cap_blocks(self):
        ag = _agent(max_persp=2)
        counts = {"CVE-1": 2}
        self.assertFalse(ag._can_analyze("CVE-1", counts))
        self.assertTrue(ag._can_analyze("CVE-2", counts))

    def test_perspective_cap_allows_own_persona_once(self):
        ag = _agent(max_persp=3)
        counts = {"CVE-1": 1}
        self.assertTrue(ag._can_analyze("CVE-1", counts))
        ag.state.analyzed_cves.add("CVE-1")
        self.assertFalse(ag._can_analyze("CVE-1", counts))

    def test_reply_skips_self_authored(self):
        ag = _agent("공격Agent")
        notifs = [
            {"commentId": 1, "cveId": "CVE-1", "authorName": "공격Agent", "content": "내 댓글"},
            {"commentId": 2, "cveId": "CVE-1", "authorName": "방어Agent", "content": "남 댓글"},
        ]
        picked = ag._pick_notification(notifs)
        self.assertEqual(picked["commentId"], 2)

    def test_score_peer_prefers_recent_high_severity(self):
        ag = _agent()
        old_low = {"id": "a", "createdAt": "2026-06-01T00:00:00Z", "commentCount": 9,
                   "severity": "low"}
        new_high = {"id": "b", "createdAt": "2026-06-13T00:00:00Z", "commentCount": 0,
                    "severity": "critical"}
        # new_high 가 더 최신(recency_rank 0)·고심각도·무댓글 → 더 높은 점수
        self.assertGreater(ag._score_peer(new_high, 0), ag._score_peer(old_low, 1))

    def test_pick_peer_spreads_across_authors(self):
        """이미 한 작성자에게 댓글을 많이 달았으면 다른 작성자를 고른다(쏠림 방지)."""
        ag = _agent("관찰자")
        ag.state.commented_authors = {"방어Agent": 3}
        community = [
            {"id": "1", "authorPersona": "방어Agent", "severity": "critical",
             "createdAt": "2026-06-20T19:00:00Z", "commentCount": 0},
            {"id": "2", "authorPersona": "공격Agent", "severity": "high",
             "createdAt": "2026-06-20T18:00:00Z", "commentCount": 0},
        ]
        picked = ag._pick_peer([dict(c) for c in community])
        self.assertEqual(picked["authorPersona"], "공격Agent")


if __name__ == "__main__":
    unittest.main()
