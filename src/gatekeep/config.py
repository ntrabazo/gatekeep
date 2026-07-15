"""Pydantic models for policies.yaml + loader. The YAML file is the governance contract;
everything tunable lives there, not in code."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel

Action = Literal["block", "redact", "allow"]


class EntropyCfg(BaseModel):
    min_length: int = 20
    threshold: float = 4.0


class PresidioCfg(BaseModel):
    enabled: bool = False


class InjectionCfg(BaseModel):
    enabled: bool = True
    mode: Literal["shadow", "enforce"] = "shadow"
    block_threshold: float = 0.8
    # Tier-2 judge seam — inert in v1; the v2 judge (PLAN-injection.md §16) reads these.
    judge_enabled: bool = False
    judge_band: tuple[float, float] = (0.3, 0.7)


class Rule(BaseModel):
    category: str
    action: Action


class RouteRule(BaseModel):
    when: Action
    model: str


class Policies(BaseModel):
    version: int
    on_parse_failure: Literal["block", "allow"] = "block"
    entropy: EntropyCfg = EntropyCfg()
    presidio: PresidioCfg = PresidioCfg()
    injection: InjectionCfg = InjectionCfg()
    rules: list[Rule]
    default_action: Action = "allow"
    routing: list[RouteRule] = []


def load_policies(path: str | Path = "policies.yaml") -> Policies:
    with open(path, encoding="utf-8") as f:
        return Policies(**yaml.safe_load(f))
