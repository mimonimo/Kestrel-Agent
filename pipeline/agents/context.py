"""Context (규칙) — 사용자 자산 인벤토리와 CVE 영향 제품을 매칭해 실제 범위를 판정한다.

자산 목록: ctx.assets(주입) 우선, 없으면 config/assets.yaml(로컬)에서 로드.
CVE 의 products[]와 매칭해:
  - affected_assets: 매칭된 자산 항목
  - in_scope: 매칭이 하나라도 있으면 True, 없으면 False
자산이 아예 없으면(미등록) in_scope=None 으로 두고 필터 없이 통과한다.
"""
from __future__ import annotations

from pipeline import assets as assets_mod
from pipeline.agents.base import register

# 매칭 토큰에서 제외할 일반어(벤더·CPE 접두 등 — 과매칭 방지)
_GENERIC = {"cpe", "the", "inc", "corp", "ltd", "server", "software", "project",
            "apache", "microsoft", "oracle", "linux", "gnu", "firmware"}


def _tokens(s: str) -> set[str]:
    raw = "".join(c if c.isalnum() else " " for c in str(s).lower()).split()
    return {t for t in raw if len(t) >= 4 and t not in _GENERIC}


def _matches(asset: str, product_join: str, product_tokens: set[str]) -> bool:
    if any(tok in product_join for tok in _tokens(asset)):
        return True
    asset_low = str(asset).lower()
    return any(tok in asset_low for tok in product_tokens)


@register(order=50)
def context(bb, ctx) -> None:  # noqa: ANN001
    inventory = list(getattr(ctx, "assets", None) or []) if ctx is not None else []
    if not inventory:
        inventory = assets_mod.load_assets()
    if not inventory:
        bb.context.in_scope = None          # 자산 미등록 — 필터 없이 통과
        bb.context.affected_assets = []
        return

    products = list((bb.enriched or {}).get("products")
                    or bb.primary_record().get("products") or [])
    product_join = " ".join(str(p).lower() for p in products)
    product_tokens: set[str] = set()
    for p in products:
        product_tokens |= _tokens(p)

    matched = [a for a in inventory if _matches(a, product_join, product_tokens)]
    bb.context.affected_assets = matched
    bb.context.in_scope = bool(matched)
