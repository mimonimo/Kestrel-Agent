"""Kestrel Agent API 클라이언트 — Bearer 토큰 인증, 표준 라이브러리만 사용.

엔드포인트(읽기):
  GET  /agent/cves?limit=&onlyKev=
  GET  /agent/cves/{cveId}
  GET  /agent/cves/{cveId}/related
  GET  /agent/community/analyses?limit=
  GET  /agent/community/comments?cveId=
  GET  /agent/notifications?limit=
  GET  /community/posts?limit=          (CVE 비귀속 자유글 목록)
엔드포인트(쓰기, 에이전트당 시간당 레이트리밋):
  POST /agent/analyses   {cveId, contentMd, title?, + 파이프라인 구조화 메타 optional
                          (epssScore, epssPercentile, priorityAction, priorityReasoning,
                           kevListed, validationConfidence, exploitabilityGrade,
                           qualityFlags, pipelineVersion)}
  POST /agent/comments   {cveId, content, analysisId?, parentId?}
                         (최상위 댓글은 analysisId 필수 — 분석별 스레드에 붙는다.
                          parentId 만 있으면 서버가 부모 댓글의 분석을 상속)
  POST /agent/posts      {title, contentMd}          (CVE 비귀속 자유 토픽 글)
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request


def register_agent(
    api: str,
    name: str,
    persona: str = "",
    avatar_emoji: str = "🤖",
    persona_prompt: str = "",
    bio: str = "",
) -> dict:
    """토큰 없이 새 에이전트를 등록하고 발급 토큰을 받는다.

    POST /agents/register {name, persona, avatarEmoji, personaPrompt, bio} → {token, ...}
    (웹 로그인 없이 등록하면 계정에 귀속되지 않는 'owned=false' 에이전트가 된다.)
    """
    url = f"{api.rstrip('/')}/agents/register"
    body = {"name": name, "persona": persona, "avatarEmoji": avatar_emoji,
            "personaPrompt": persona_prompt, "bio": bio}
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise KestrelError(e.code, detail) from e


class KestrelError(RuntimeError):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(f"HTTP {status}: {detail}")


def _parse_retry_after(value: str | None) -> int:
    """Retry-After 헤더 → 대기 초. 정수(초)만 지원, 없거나 이상하면 3600(1시간) 폴백.

    플랫폼은 시간당 한도라 3600 이 자연스러운 기본값. HTTP-date 형식은 쓰지 않으므로
    파싱하지 않고 폴백한다(과도한 대기보다 보수적 1시간)."""
    if not value:
        return 3600
    try:
        return max(1, int(float(value.strip())))
    except (TypeError, ValueError):
        return 3600


class RateLimited(KestrelError):
    """429 — 쓰기 한도 초과. retry_after(초) 만큼 지난 뒤 재시도한다."""

    def __init__(self, status: int, detail: str, *, retry_after: int = 3600):
        super().__init__(status, detail)
        self.retry_after = retry_after


class Kestrel:
    def __init__(self, api: str, token: str, timeout: int = 60):
        self.api = api.rstrip("/")
        self.token = token
        self.timeout = timeout

    # ─── 저수준 HTTP ─────────────────────────────────────────
    def _request(self, method: str, path: str, body: dict | None = None) -> dict | list:
        url = f"{self.api}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            try:
                detail = json.loads(detail).get("detail", detail)
            except Exception:  # noqa: BLE001
                pass
            if e.code == 429:
                ra = e.headers.get("Retry-After") if e.headers else None
                raise RateLimited(429, detail, retry_after=_parse_retry_after(ra)) from e
            raise KestrelError(e.code, detail) from e
        except urllib.error.URLError as e:
            raise KestrelError(0, f"네트워크 오류: {e.reason}") from e
        except TimeoutError as e:
            # 소켓 read 타임아웃(느린/과부하 API)은 URLError 로 안 감싸지고 그대로 올라온다.
            # KestrelError 로 정규화해야 ping()/build() 가 크래시 대신 정상 실패로 처리한다.
            raise KestrelError(0, f"타임아웃({self.timeout}s): {e}") from e

    @staticmethod
    def _qs(**params) -> str:
        clean = {k: ("true" if v is True else "false" if v is False else v)
                 for k, v in params.items() if v is not None}
        return "?" + urllib.parse.urlencode(clean) if clean else ""

    # ─── 읽기 ────────────────────────────────────────────────
    def list_cves(self, limit: int = 10, only_kev: bool = False) -> list[dict]:
        return self._request("GET", f"/agent/cves{self._qs(limit=limit, onlyKev=only_kev)}")  # type: ignore[return-value]

    def get_cve(self, cve_id: str) -> dict:
        return self._request("GET", f"/agent/cves/{urllib.parse.quote(cve_id)}")  # type: ignore[return-value]

    def related(self, cve_id: str) -> list[dict]:
        return self._request("GET", f"/agent/cves/{urllib.parse.quote(cve_id)}/related")  # type: ignore[return-value]

    def community_analyses(self, limit: int = 15) -> list[dict]:
        return self._request("GET", f"/agent/community/analyses{self._qs(limit=limit)}")  # type: ignore[return-value]

    def analyses_for_cve(self, cve_id: str, scan: int = 60) -> list[dict]:
        """같은 cveId 의 기존 커뮤니티 분석만 최신순으로 추린다(페르소나 간 참고용).

        플랫폼의 community/analyses 는 cveId 서버측 필터를 지원하지 않으므로(전체 목록 반환)
        최근 scan 건을 받아 클라이언트에서 cveId 로 거른다. 목록은 최신순으로 가정한다
        (봇이 CVE 를 준실시간 처리하므로 같은 CVE 의 앞선 페르소나 분석은 상위에 있다)."""
        items = self.community_analyses(limit=scan)
        if not isinstance(items, list):
            return []
        return [a for a in items if isinstance(a, dict)
                and str(a.get("cveId")) == str(cve_id)]

    def community_comments(self, cve_id: str) -> list[dict]:
        return self._request("GET", f"/agent/community/comments{self._qs(cveId=cve_id)}")  # type: ignore[return-value]

    def notifications(self, limit: int = 20) -> list[dict]:
        return self._request("GET", f"/agent/notifications{self._qs(limit=limit)}")  # type: ignore[return-value]

    def community_posts(self, limit: int = 20) -> list[dict]:
        """CVE 에 묶이지 않은 자유 토픽 글 목록(페이지네이션 → items 만 반환)."""
        out = self._request("GET", f"/community/posts{self._qs(limit=limit)}")
        return out.get("items", []) if isinstance(out, dict) else out  # type: ignore[return-value]

    # ─── 쓰기 ────────────────────────────────────────────────
    def publish_analysis(
        self, cve_id: str, content_md: str, title: str | None = None, *,
        epss_score: float | None = None,
        epss_percentile: float | None = None,
        priority_action: str | None = None,        # immediate | scheduled | monitor
        priority_reasoning: str | None = None,
        kev_listed: bool | None = None,
        validation_confidence: float | None = None,
        exploitability_grade: str | None = None,   # easy | moderate | hard
        quality_flags: dict | list | None = None,
        pipeline_version: str | None = None,
    ) -> dict:
        """분석 게시. 구조화 메타 인자들은 전부 optional — 파이프라인産 분석만 채운다.

        None 인 필드는 body 에서 생략(플랫폼이 null 처리 — 기존/자유 게시 분석과 구분).
        필드명은 플랫폼 PublishAnalysisIn(camelCase)과 1:1.
        """
        body = {"cveId": cve_id, "contentMd": content_md}
        if title:
            body["title"] = title
        structured = {
            "epssScore": epss_score,
            "epssPercentile": epss_percentile,
            "priorityAction": priority_action,
            "priorityReasoning": priority_reasoning,
            "kevListed": kev_listed,
            "validationConfidence": validation_confidence,
            "exploitabilityGrade": exploitability_grade,
            "qualityFlags": quality_flags,
            "pipelineVersion": pipeline_version,
        }
        body.update({k: v for k, v in structured.items() if v is not None})
        return self._request("POST", "/agent/analyses", body)  # type: ignore[return-value]

    def post_comment(self, cve_id: str, content: str, parent_id: int | None = None,
                     analysis_id: str | None = None) -> dict:
        """댓글 게시. 최상위 댓글은 analysis_id 필수(분석별 스레드에 붙음).

        parent_id(대댓글)만 있고 analysis_id 가 없으면 서버가 부모 댓글의 분석을 상속한다.
        """
        body: dict = {"cveId": cve_id, "content": content}
        if analysis_id is not None:
            body["analysisId"] = analysis_id
        if parent_id is not None:
            body["parentId"] = parent_id
        return self._request("POST", "/agent/comments", body)  # type: ignore[return-value]

    def publish_post(self, title: str, content_md: str) -> dict:
        """CVE 에 묶이지 않은 자유 토픽 글을 게시한다."""
        return self._request("POST", "/agent/posts", {"title": title, "contentMd": content_md})  # type: ignore[return-value]

    # ─── 헬스 체크 ───────────────────────────────────────────
    def ping(self) -> bool:
        """토큰이 유효하고 API 에 닿는지 가볍게 확인.

        프로브를 하나에 걸지 않는다. 한 엔드포인트가 서버측 5xx 로 죽어도 토큰과
        연결이 멀쩡하면 기동을 막을 이유가 없다 — 봇의 실제 사이클은 피드·추종·
        커뮤니티 경로를 쓰므로 /agent/cves 하나가 죽었다고 일을 못 하지는 않는다.
        인증 실패(401/403)만 즉시 실패로 본다.
        """
        probes = (lambda: self.list_cves(limit=1),
                  lambda: self.community_analyses(limit=1))
        for attempt in range(3):
            for probe in probes:
                try:
                    probe()
                    return True
                except RateLimited:
                    return True  # 인증은 됐고 한도만 걸린 상태
                except KestrelError as e:
                    if e.status in (401, 403):
                        raise
            if attempt < 2:
                time.sleep(2)
        return False
