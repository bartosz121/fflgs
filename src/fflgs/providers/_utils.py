import logging
from typing import Any

from fflgs.core import Condition, Flag, Rule, RuleGroup

logger = logging.getLogger(__name__)


def deserialize_condition(data: dict[str, Any]) -> Condition:
    return Condition(
        ctx_attr=data["ctx_attr"],
        operator=data["operator"],
        value=data["value"],
        active=data["active"],
    )


def deserialize_rule(data: dict[str, Any]) -> Rule:
    return Rule(
        operator=data["operator"],
        conditions=[deserialize_condition(cond) for cond in data["conditions"]],
        active=data["active"],
    )


def deserialize_rule_group(data: dict[str, Any]) -> RuleGroup:
    return RuleGroup(
        operator=data["operator"],
        rules=[deserialize_rule(rule) for rule in data["rules"]],
        active=data["active"],
    )


def deserialize_flag(data: dict[str, Any]) -> Flag:
    return Flag(
        name=data["name"],
        description=data.get("description"),
        rules_strategy=data["rules_strategy"],
        rule_groups=[deserialize_rule_group(rg) for rg in data["rule_groups"]],
        enabled=data["enabled"],
        version=data["version"],
    )
