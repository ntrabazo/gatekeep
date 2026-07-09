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
    rules: list[Rule]
    default_action: Action = "allow"
    routing: list[RouteRule] = []


def load_policies(path: str | Path = "policies.yaml") -> Policies:
    with open(path, encoding="utf-8") as f:
        return Policies(**yaml.safe_load(f))
