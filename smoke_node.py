#!/usr/bin/env python3
"""새 노드 스모크 테스트 — CVE 1건을 파이프라인에 통과시키되 **게시는 하지 않는다**.

    .venv/bin/python smoke_node.py                 # 기본 페르소나(defensive)
    .venv/bin/python smoke_node.py --persona offensive

왜 `agent.py --once` 대신 이걸 쓰는가: `--once` 는 실제로 커뮤니티에 글을 올린다.
설정이 틀린 상태로 올라간 글은 지울 수도 없고 표본도 오염시킨다. 여기서는 Supervisor 를
직접 호출하므로 게시 경로(`publish_analysis`)를 아예 타지 않는다.

이게 통과하면 새 노드에서 확인되는 것:
  - Ollama 연결 + 모델 로드 + 실제 생성 속도(리포트 1건 소요 시간)
  - thinking 모델 함정(OLLAMA_THINK=true 로 본문이 비는 문제)
  - 8개 노드 파이프라인 전체가 이 환경에서 완주하는지
게시·토큰·레이트리밋은 확인되지 않는다 — 그건 서비스를 띄운 뒤 로그로 본다.
"""
from __future__ import annotations

import argparse
import tempfile
import time

from config import Config
from pipeline.state import Blackboard, PipelineContext
from pipeline.supervisor import Supervisor

# 네트워크 없이도 돌도록 입력을 고정 — Collector 는 kestrel=None 이면 시드를 그대로 쓴다.
# Log4Shell 을 쓰는 이유: KEV 등재 + CVSS 10.0 + 체이닝 소재가 많아 모든 노드가 실제로
# 일을 하게 만드는 입력이다. 조용한 CVE 로는 파이프라인이 빈손으로 통과해도 모른다.
SEED = {
    "cveId": "CVE-2021-44228",
    "severity": "critical",
    "cvssScore": 10.0,
    "cvssVector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "kevListed": True,
    "types": ["CWE-502", "CWE-917"],
    "products": ["Apache Log4j 2.0-beta9 ~ 2.14.1"],
    "description": (
        "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and "
        "other JNDI related endpoints, allowing remote code execution when message lookup "
        "substitution is enabled."
    ),
}


def main() -> int:
    ap = argparse.ArgumentParser(description="게시 없이 파이프라인 1회 실행(노드 검증용)")
    ap.add_argument("--persona", default="defensive",
                    help="defensive | offensive | analyst (기본 defensive)")
    args = ap.parse_args()

    cfg = Config.from_env()
    if cfg.backend != "ollama":
        print(f"⚠️  AGENT_BACKEND={cfg.backend} — 이 스크립트는 ollama 기준입니다.")
    model = cfg.analysis_model or cfg.ollama_model
    print(f"· host={cfg.ollama_host}  model={model}  think={cfg.ollama_think}")
    if cfg.ollama_think:
        print("⚠️  OLLAMA_THINK=true 입니다. thinking 모델이면 리포트 본문이 빌 수 있습니다.")

    from llm import OllamaClient
    client = OllamaClient(cfg)

    bb = Blackboard(cve_id=SEED["cveId"], persona=args.persona)
    bb.source_records.append(
        {"source": "seed", "kind": "primary", "cveId": SEED["cveId"], "data": SEED}
    )
    with tempfile.TemporaryDirectory() as tmp:      # validation_events 등이 repo 를 더럽히지 않게
        ctx = PipelineContext(
            cfg=cfg, kestrel=None, llm=client, model=model,
            report_lang="ko", data_dir=tmp,
            # 동료 조회는 kestrel=None 이라 어차피 안 되지만, 의도를 명시해 둔다.
            peer_reference=False,
        )
        t0 = time.time()
        Supervisor().run(bb, ctx)
        elapsed = time.time() - t0

    print(f"\n· 소요 {elapsed:.0f}초")
    print(f"· 노드 실행: {' → '.join(a.get('agent', '?') for a in bb.audit_log)}")
    print(f"· 등급={bb.exploitability.grade}  조치={bb.priority.action}  "
          f"검증신뢰도={bb.validation.confidence}")
    print(f"· 검증 통과={bb.verification.passed}  실패항목={bb.verification.failures}")

    body = "\n".join(filter(None, [bb.report.attack, bb.report.impact, bb.report.chaining,
                                   bb.report.detection, bb.report.mitigation]))
    print(f"· 본문 {len(body)}자 / 영문요약 {len(bb.report.summary_en or '')}자")
    if bb.report.meta.get("error"):
        print(f"\n❌ 리포트 오류: {bb.report.meta['error']}")
        return 1
    if len(body) < 500:
        print("\n❌ 본문이 너무 짧습니다. thinking 모델인데 OLLAMA_THINK 가 켜져 있거나, "
              "모델이 한국어 지시를 못 따르는 경우입니다.")
        print(f"--- 받은 본문 ---\n{body}\n")
        return 1

    print(f"\n--- 공격 기법(앞 400자) ---\n{(bb.report.attack or '')[:400]}")
    print(f"\n✅ 통과. 리포트 1건 ≈ {elapsed:.0f}초 → AGENT_INTERVAL 은 "
          f"페르소나 수 × {elapsed:.0f}초 이상을 권장합니다(GPU 직렬 공유).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
