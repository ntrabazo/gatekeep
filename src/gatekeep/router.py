"""Model routing: swap the requested model based on the policy decision.
Rule matching is literal string equality on Decision.action; first match wins."""

from .config import Policies
from .policy import Decision


def route_model(requested: str, decision: Decision, policies: Policies) -> str:
    for rule in policies.routing:
        if rule.when == decision.action:
            return rule.model
    return requested
