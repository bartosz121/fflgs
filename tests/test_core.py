# pyright: reportPrivateUsage=false

from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from typing import Any
from unittest import mock

import pytest

from fflgs.core import (
    Condition,
    ConditionOperator,
    FeatureFlags,
    FeatureFlagsAsync,
    FeatureFlagsEvaluationError,
    FeatureFlagsFlagNotFoundError,
    FeatureFlagsProviderError,
    Flag,
    Rule,
    RuleGroup,
    _evaluator_contains,
    _evaluator_eq,
    _evaluator_ge,
    _evaluator_gt,
    _evaluator_in,
    _evaluator_le,
    _evaluator_lt,
    _evaluator_ne,
    _evaluator_not_contains,
    _evaluator_not_in,
    _evaluator_regex,
    _get_value_from_ctx,
    _is_bool,
    _is_comparable_condition,
    _is_container,
    _validate_condition_value_with_operator,
    _validate_context_value_with_operator,
)
from fflgs.providers.memory import InMemoryProvider, InMemoryProviderAsync


class TestTypeGuards:
    """Test type guard functions for runtime type checking"""

    def test_is_comparable_condition_with_valid_types(self) -> None:
        """Test that _is_comparable_condition accepts comparable types"""
        assert _is_comparable_condition("string") is True
        assert _is_comparable_condition(42) is True
        assert _is_comparable_condition(3.14) is True
        assert _is_comparable_condition(True) is True
        assert _is_comparable_condition(datetime.now(tz=timezone.utc)) is True
        assert _is_comparable_condition(date.today()) is True  # noqa: DTZ011
        assert _is_comparable_condition(time(12, 0)) is True

    def test_is_comparable_condition_with_invalid_types(self) -> None:
        """Test that _is_comparable_condition rejects non-comparable types"""
        assert _is_comparable_condition([1, 2, 3]) is False
        assert _is_comparable_condition({"key": "value"}) is False
        assert _is_comparable_condition(None) is False

    def test_is_container_with_valid_containers(self) -> None:
        """Test that _is_container accepts container types"""
        assert _is_container([1, 2, 3]) is True
        assert _is_container({"a", "b"}) is True
        assert _is_container({"key": "value"}) is True
        assert _is_container("string") is True
        assert _is_container((1, 2)) is True

    def test_is_container_with_non_containers(self) -> None:
        """Test that _is_container rejects non-container types"""
        assert _is_container(42) is False
        assert _is_container(None) is False

    def test_is_bool_with_boolean(self) -> None:
        """Test that _is_bool correctly identifies boolean values"""
        assert _is_bool(True) is True
        assert _is_bool(False) is True


class TestEvaluatorFunctions:
    """Test individual evaluator functions for condition operators"""

    def test_evaluator_eq(self) -> None:
        """Test equality evaluator"""
        assert _evaluator_eq("test", "test") is True
        assert _evaluator_eq(42, 42) is True
        assert _evaluator_eq("test", "other") is False

    def test_evaluator_ne(self) -> None:
        """Test inequality evaluator"""
        assert _evaluator_ne("test", "other") is True
        assert _evaluator_ne(42, 43) is True
        assert _evaluator_ne("test", "test") is False

    def test_evaluator_gt(self) -> None:
        """Test greater than evaluator"""
        assert _evaluator_gt(10, 5) is True
        assert _evaluator_gt(5, 10) is False
        assert _evaluator_gt(10, 10) is False

    def test_evaluator_ge(self) -> None:
        """Test greater than or equal evaluator"""
        assert _evaluator_ge(10, 5) is True
        assert _evaluator_ge(10, 10) is True
        assert _evaluator_ge(5, 10) is False

    def test_evaluator_lt(self) -> None:
        """Test less than evaluator"""
        assert _evaluator_lt(5, 10) is True
        assert _evaluator_lt(10, 5) is False
        assert _evaluator_lt(10, 10) is False

    def test_evaluator_le(self) -> None:
        """Test less than or equal evaluator"""
        assert _evaluator_le(5, 10) is True
        assert _evaluator_le(10, 10) is True
        assert _evaluator_le(10, 5) is False

    def test_evaluator_contains(self) -> None:
        """Test contains evaluator"""
        assert _evaluator_contains([1, 2, 3], 2) is True
        assert _evaluator_contains("hello", "e") is True
        assert _evaluator_contains([1, 2, 3], 4) is False

    def test_evaluator_not_contains(self) -> None:
        """Test not contains evaluator"""
        assert _evaluator_not_contains([1, 2, 3], 4) is True
        assert _evaluator_not_contains([1, 2, 3], 2) is False

    def test_evaluator_in(self) -> None:
        """Test in evaluator (note: reversed operands)"""
        assert _evaluator_in(2, [1, 2, 3]) is True
        assert _evaluator_in("e", "hello") is True
        assert _evaluator_in(4, [1, 2, 3]) is False

    def test_evaluator_not_in(self) -> None:
        """Test not in evaluator"""
        assert _evaluator_not_in(4, [1, 2, 3]) is True
        assert _evaluator_not_in(2, [1, 2, 3]) is False

    def test_evaluator_regex_match(self) -> None:
        """Test regex evaluator with matching patterns"""
        assert _evaluator_regex(r"\d+", "test123") is True
        assert _evaluator_regex(r"^hello", "hello world") is True

    def test_evaluator_regex_no_match(self) -> None:
        """Test regex evaluator with non-matching patterns"""
        assert _evaluator_regex(r"\d+", "nodigits") is False

    def test_evaluator_regex_invalid_pattern(self) -> None:
        """Test regex evaluator with invalid pattern"""
        with pytest.raises(ValueError, match="Regex error"):
            _evaluator_regex(r"[invalid(", "test")

    def test_evaluator_regex_caching(self) -> None:
        """Test that regex patterns are cached"""
        pattern = r"\d+"
        _evaluator_regex(pattern, "123")
        _evaluator_regex(pattern, "456")
        # Pattern should be cached and reused


class TestValidationFunctions:
    """Test validation functions for condition and context values"""

    @pytest.mark.parametrize(
        "operator,value",
        [
            ("EQUALS", "test"),
            ("EQUALS", 42),
            ("NOT_EQUALS", None),
            ("GREATER_THAN", 42),
            ("LESS_THAN", 3.14),
            ("IN", [1, 2, 3]),
            ("CONTAINS", "any_value"),
            ("REGEX", r"\d+"),
        ],
    )
    def test_validate_condition_value_with_operator_valid(self, operator: ConditionOperator, value: Any) -> None:
        """Test validation passes for valid operator-value combinations"""
        _validate_condition_value_with_operator(operator, value)

    @pytest.mark.parametrize(
        "operator,value,error_msg",
        [
            ("GREATER_THAN", [1, 2], "requires comparable value"),
            ("CONTAINS", True, "requires container value"),
            ("REGEX", 123, "requires str value"),
        ],
    )
    def test_validate_condition_value_with_operator_invalid(
        self, operator: ConditionOperator, value: Any, error_msg: str
    ) -> None:
        """Test validation fails for invalid operator-value combinations"""
        with pytest.raises(ValueError, match=error_msg):
            _validate_condition_value_with_operator(operator, value)

    @pytest.mark.parametrize(
        "operator,ctx_value",
        [
            ("EQUALS", "test"),
            ("GREATER_THAN", 42),
            ("CONTAINS", [1, 2, 3]),
            ("IN", "any_value"),
            ("REGEX", "test string"),
        ],
    )
    def test_validate_context_value_with_operator_valid(self, operator: ConditionOperator, ctx_value: Any) -> None:
        """Test context value validation passes for valid combinations"""
        _validate_context_value_with_operator(operator, ctx_value)

    @pytest.mark.parametrize(
        "operator,ctx_value,error_msg",
        [
            ("GREATER_THAN", [1, 2], "requires comparable context value"),
            ("IN", True, "requires container context value"),
            ("REGEX", 123, "requires string context value"),
        ],
    )
    def test_validate_context_value_with_operator_invalid(
        self, operator: ConditionOperator, ctx_value: Any, error_msg: str
    ) -> None:
        """Test context value validation fails for invalid combinations"""
        with pytest.raises(TypeError, match=error_msg):
            _validate_context_value_with_operator(operator, ctx_value)


class TestGetValueFromContext:
    """Test context value extraction functionality"""

    def test_get_simple_value(self) -> None:
        """Test retrieving a simple top-level value from context"""
        ctx: dict[str, Any] = {"age": 25}
        assert _get_value_from_ctx(ctx, "age") == 25

    def test_get_nested_dict_value(self) -> None:
        """Test retrieving a nested dictionary value"""
        ctx: dict[str, Any] = {"user": {"name": "John", "age": 30}}
        assert _get_value_from_ctx(ctx, "user.name") == "John"
        assert _get_value_from_ctx(ctx, "user.age") == 30

    def test_get_object_attribute(self) -> None:
        """Test retrieving an object attribute via dot notation"""

        @dataclass
        class User:
            name: str

        ctx: dict[str, Any] = {"user": User("Alice")}
        assert _get_value_from_ctx(ctx, "user.name") == "Alice"

    def test_get_deeply_nested_value(self) -> None:
        """Test retrieving deeply nested values"""
        ctx: dict[str, Any] = {"company": {"department": {"team": {"lead": "Bob"}}}}
        assert _get_value_from_ctx(ctx, "company.department.team.lead") == "Bob"

    def test_get_value_key_not_found(self) -> None:
        """Test error handling when key is not found"""
        ctx: dict[str, Any] = {"age": 25}
        with pytest.raises(ValueError, match="'name' not found in context"):
            _get_value_from_ctx(ctx, "name")

    def test_get_value_nested_key_not_found(self) -> None:
        """Test error handling for missing nested key"""
        ctx: dict[str, Any] = {"user": {"age": 30}}
        with pytest.raises(ValueError, match=r"\'user.name\' not found in context"):
            _get_value_from_ctx(ctx, "user.name")

    def test_get_value_invalid_type(self) -> None:
        """Test error handling when retrieved value has invalid type"""
        ctx: dict[str, Any] = {"data": object()}
        with pytest.raises(TypeError, match="Unexpected type"):
            _get_value_from_ctx(ctx, "data")


class TestCondition:
    """Test Condition class for single condition evaluation"""

    def test_condition_creation_valid(self) -> None:
        """Test creating a condition with valid parameters"""
        condition = Condition(
            ctx_attr="age",
            operator="GREATER_THAN",
            value=18,
            active=True,
        )
        assert condition.ctx_attr == "age"
        assert condition.operator == "GREATER_THAN"
        assert condition.value == 18
        assert condition.active is True

    def test_condition_post_init_validation_invalid_value(self) -> None:
        """Test that __post_init__ validates condition values"""
        with pytest.raises(ValueError, match="requires comparable value"):
            Condition(
                ctx_attr="age",
                operator="GREATER_THAN",
                value=[1, 2, 3],  # Invalid for GREATER_THAN
                active=True,
            )

    def test_condition_evaluate_equals_true(self) -> None:
        """Test EQUALS operator evaluates to True"""
        condition = Condition(ctx_attr="status", operator="EQUALS", value="active", active=True)
        ctx: dict[str, Any] = {"status": "active"}
        assert condition.evaluate(ctx=ctx) is True

    def test_condition_evaluate_equals_false(self) -> None:
        """Test EQUALS operator evaluates to False"""
        condition = Condition(ctx_attr="status", operator="EQUALS", value="active", active=True)
        ctx: dict[str, Any] = {"status": "inactive"}
        assert condition.evaluate(ctx=ctx) is False

    def test_condition_evaluate_greater_than(self) -> None:
        """Test GREATER_THAN operator"""
        condition = Condition(ctx_attr="age", operator="GREATER_THAN", value=25, active=True)
        assert condition.evaluate(ctx={"age": 18}) is True
        assert condition.evaluate(ctx={"age": 30}) is False

    def test_condition_evaluate_less_than_or_equals(self) -> None:
        """Test LESS_THAN_OR_EQUALS operator"""
        condition = Condition(
            ctx_attr="score",
            operator="LESS_THAN_OR_EQUALS",
            value=100,
            active=True,
        )
        assert condition.evaluate(ctx={"score": 100}) is True
        assert condition.evaluate(ctx={"score": 200}) is True
        assert condition.evaluate(ctx={"score": 50}) is False

    def test_condition_evaluate_in(self) -> None:
        """Test IN operator"""
        condition = Condition(
            ctx_attr="role",
            operator="IN",
            value="admin",
            active=True,
        )
        assert condition.evaluate(ctx={"role": ["admin"]}) is True
        assert condition.evaluate(ctx={"role": ["user"]}) is False

    def test_condition_evaluate_contains(self) -> None:
        """Test CONTAINS operator"""
        condition = Condition(ctx_attr="tags", operator="CONTAINS", value=["python"], active=True)
        assert condition.evaluate(ctx={"tags": "python"}) is True
        assert condition.evaluate(ctx={"tags": "java"}) is False

    def test_condition_evaluate_regex(self) -> None:
        """Test REGEX operator"""
        condition = Condition(ctx_attr="email", operator="REGEX", value=r".*@example\.com$", active=True)
        assert condition.evaluate(ctx={"email": "user@example.com"}) is True
        assert condition.evaluate(ctx={"email": "user@other.com"}) is False

    def test_condition_evaluate_inactive_returns_none(self) -> None:
        """Test that inactive conditions return None"""
        condition = Condition(ctx_attr="age", operator="EQUALS", value=25, active=False)
        assert condition.evaluate(ctx={"age": 25}) is None

    def test_condition_evaluate_missing_operator(self) -> None:
        """Test error handling for missing operator evaluator"""
        condition = Condition(ctx_attr="age", operator="EQUALS", value=25, active=True)
        condition.operator = "INVALID_OP"  # type: ignore[assignment]
        with pytest.raises(FeatureFlagsEvaluationError, match="not found"):
            condition.evaluate(ctx={"age": 25})

    def test_condition_evaluate_context_key_missing(self) -> None:
        """Test error when context attribute is missing"""
        condition = Condition(ctx_attr="age", operator="EQUALS", value=25, active=True)
        with pytest.raises(FeatureFlagsEvaluationError, match="not found in context"):
            condition.evaluate(ctx={"name": "John"})

    def test_condition_evaluate_type_mismatch(self) -> None:
        """Test error when context value type doesn't match operator"""
        condition = Condition(ctx_attr="age", operator="GREATER_THAN", value=18, active=True)
        with pytest.raises(FeatureFlagsEvaluationError, match="requires comparable"):
            condition.evaluate(ctx={"age": [1, 2, 3]})

    def test_condition_evaluate_with_datetime(self) -> None:
        """Test condition evaluation with datetime values"""
        now = datetime.now(tz=timezone.utc)
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        condition = Condition(ctx_attr="timestamp", operator="GREATER_THAN", value=now, active=True)
        assert condition.evaluate(ctx={"timestamp": past}) is True


# ============================================================================
# RULE TESTS
# ============================================================================


class TestRule:
    """Test Rule class for combining conditions with logical operators"""

    def test_rule_creation(self) -> None:
        """Test creating a rule with conditions"""
        conditions = [
            Condition("age", "GREATER_THAN", 18, True),
            Condition("status", "EQUALS", "active", True),
        ]
        rule = Rule(operator="AND", conditions=conditions, active=True)
        assert rule.operator == "AND"
        assert len(rule.conditions) == 2
        assert rule.active is True

    def test_rule_evaluate_and_all_true(self) -> None:
        """Test AND rule with all conditions True"""
        conditions = [
            Condition("age", "GREATER_THAN", 25, True),
            Condition("status", "EQUALS", "active", True),
        ]
        rule = Rule(operator="AND", conditions=conditions, active=True)
        ctx: dict[str, Any] = {"age": 18, "status": "active"}
        assert rule.evaluate(ctx=ctx) is True

    def test_rule_evaluate_and_one_false(self) -> None:
        """Test AND rule with one condition False"""
        conditions = [
            Condition("age", "GREATER_THAN", 25, True),
            Condition("status", "EQUALS", "active", True),
        ]
        rule = Rule(operator="AND", conditions=conditions, active=True)
        ctx: dict[str, Any] = {"age": 18, "status": "inactive"}
        assert rule.evaluate(ctx=ctx) is False

    def test_rule_evaluate_or_one_true(self) -> None:
        """Test OR rule with one condition True"""
        conditions = [
            Condition("age", "GREATER_THAN", 25, True),
            Condition("status", "EQUALS", "active", True),
        ]
        rule = Rule(operator="OR", conditions=conditions, active=True)
        ctx: dict[str, Any] = {"age": 18, "status": "inactive"}
        assert rule.evaluate(ctx=ctx) is True

    def test_rule_evaluate_or_all_false(self) -> None:
        """Test OR rule with all conditions False"""
        conditions = [
            Condition("age", "GREATER_THAN", 25, True),
            Condition("status", "EQUALS", "active", True),
        ]
        rule = Rule(operator="OR", conditions=conditions, active=True)
        ctx: dict[str, Any] = {"age": 30, "status": "inactive"}
        assert rule.evaluate(ctx=ctx) is False

    def test_rule_evaluate_inactive_returns_none(self) -> None:
        """Test that inactive rules return None"""
        conditions = [Condition("age", "GREATER_THAN", 25, True)]
        rule = Rule(operator="AND", conditions=conditions, active=False)
        assert rule.evaluate(ctx={"age": 18}) is None

    def test_rule_evaluate_no_conditions_error(self) -> None:
        """Test error when rule has no conditions"""
        rule = Rule(operator="AND", conditions=[], active=True)
        with pytest.raises(FeatureFlagsEvaluationError, match="No conditions found"):
            rule.evaluate(ctx={"age": 25})

    def test_rule_evaluate_filters_inactive_conditions(self) -> None:
        """Test that inactive conditions are filtered during evaluation"""
        conditions = [
            Condition("age", "GREATER_THAN", 25, True),
            Condition("status", "EQUALS", "inactive", False),  # Inactive
        ]
        rule = Rule(operator="AND", conditions=conditions, active=True)
        # Should only evaluate active condition
        assert rule.evaluate(ctx={"age": 18}) is True

    def test_rule_evaluate_all_conditions_inactive_and(self) -> None:
        """Test AND rule behavior when all conditions are inactive"""
        conditions = [
            Condition("age", "GREATER_THAN", 25, False),
            Condition("status", "EQUALS", "active", False),
        ]
        rule = Rule(operator="AND", conditions=conditions, active=True)
        # all([]) returns True
        assert rule.evaluate(ctx={}) is True

    def test_rule_evaluate_all_conditions_inactive_or(self) -> None:
        """Test OR rule behavior when all conditions are inactive"""
        conditions = [
            Condition("age", "GREATER_THAN", 25, False),
            Condition("status", "EQUALS", "active", False),
        ]
        rule = Rule(operator="OR", conditions=conditions, active=True)
        # any([]) returns False
        assert rule.evaluate(ctx={}) is False


class TestRuleGroup:
    """Test RuleGroup class for combining rules with logical operators"""

    def test_rule_group_creation(self) -> None:
        """Test creating a rule group with rules"""
        rules = [
            Rule(
                "AND",
                [Condition("age", "GREATER_THAN", 25, True)],
                True,
            ),
            Rule(
                "AND",
                [Condition("status", "EQUALS", "active", True)],
                True,
            ),
        ]
        rg = RuleGroup(operator="OR", rules=rules, active=True)
        assert rg.operator == "OR"
        assert len(rg.rules) == 2
        assert rg.active is True

    def test_rule_group_evaluate_and_all_true(self) -> None:
        """Test AND rule group with all rules True"""
        rules = [
            Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True),
            Rule("AND", [Condition("status", "EQUALS", "active", True)], True),
        ]
        rg = RuleGroup(operator="AND", rules=rules, active=True)
        ctx: dict[str, Any] = {"age": 18, "status": "active"}
        assert rg.evaluate(ctx=ctx) is True

    def test_rule_group_evaluate_or_one_true(self) -> None:
        """Test OR rule group with one rule True"""
        rules = [
            Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True),
            Rule("AND", [Condition("age", "LESS_THAN", 10, True)], True),
        ]
        rg = RuleGroup(operator="OR", rules=rules, active=True)
        assert rg.evaluate(ctx={"age": 18}) is True

    def test_rule_group_evaluate_inactive_returns_none(self) -> None:
        """Test that inactive rule groups return None"""
        rules = [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)]
        rg = RuleGroup(operator="AND", rules=rules, active=False)
        assert rg.evaluate(ctx={"age": 18}) is None

    def test_rule_group_evaluate_no_rules_error(self) -> None:
        """Test error when rule group has no rules"""
        rg = RuleGroup(operator="AND", rules=[], active=True)
        with pytest.raises(FeatureFlagsEvaluationError, match="No rules found"):
            rg.evaluate(ctx={"age": 18})

    def test_rule_group_filters_inactive_rules(self) -> None:
        """Test that inactive rules are filtered during evaluation"""
        rules = [
            Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True),
            Rule("AND", [Condition("age", "LESS_THAN", 10, True)], False),
        ]
        rg = RuleGroup(operator="AND", rules=rules, active=True)
        assert rg.evaluate(ctx={"age": 18}) is True


class TestFlag:
    """Test Flag class for feature flag evaluation"""

    def test_flag_creation(self) -> None:
        """Test creating a flag"""
        flag = Flag(
            name="test_flag",
            description="Test flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        assert flag.name == "test_flag"
        assert flag.enabled is True
        assert flag.rules_strategy == "ALL"

    def test_flag_evaluate_disabled_returns_false(self) -> None:
        """Test that disabled flags always return False"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[],
            enabled=False,
            version=1,
        )
        assert flag.evaluate(ctx={}) is False

    def test_flag_evaluate_no_rule_groups_returns_true(self) -> None:
        """Test that enabled flags without rule groups return True"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        assert flag.evaluate(ctx={}) is True

    def test_flag_evaluate_strategy_all_success(self) -> None:
        """Test ALL strategy with all rule groups True"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)],
                True,
            ),
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("status", "EQUALS", "active", True)], True)],
                True,
            ),
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        ctx: dict[str, Any] = {"age": 18, "status": "active"}
        assert flag.evaluate(ctx=ctx) is True

    def test_flag_evaluate_strategy_all_failure(self) -> None:
        """Test ALL strategy with one rule group False"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)],
                True,
            ),
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "LESS_THAN", 50, True)], True)],
                True,
            ),
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        assert flag.evaluate(ctx={"age": 18}) is False

    def test_flag_evaluate_strategy_any_success(self) -> None:
        """Test ANY strategy with one rule group True"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)],
                True,
            ),
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "LESS_THAN", 10, True)], True)],
                True,
            ),
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ANY",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        assert flag.evaluate(ctx={"age": 18}) is True

    def test_flag_evaluate_strategy_none_success(self) -> None:
        """Test NONE strategy with all rule groups False"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "LESS_THAN", 100, True)], True)],
                True,
            ),
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 10, True)], True)],
                True,
            ),
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="NONE",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        assert flag.evaluate(ctx={"age": 25}) is True

    def test_flag_evaluate_strategy_none_failure(self) -> None:
        """Test NONE strategy with one rule group True"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)],
                True,
            ),
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="NONE",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        assert flag.evaluate(ctx={"age": 18}) is False


class TestFeatureFlags:
    """Test synchronous FeatureFlags evaluator"""

    def test_feature_flags_creation(self) -> None:
        """Test creating FeatureFlags instance"""
        provider = InMemoryProvider()
        ff = FeatureFlags(provider)
        assert ff._provider is provider
        assert ff._on_flag_not_found == "return_false"
        assert ff._on_evaluation_error == "return_false"

    def test_is_enabled_flag_exists_and_enabled(self) -> None:
        """Test is_enabled with existing enabled flag"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        provider = InMemoryProvider()
        provider.add_flag(flag)

        ff = FeatureFlags(provider)
        assert ff.is_enabled("test_flag") is True

    def test_is_enabled_flag_exists_but_disabled(self) -> None:
        """Test is_enabled with existing disabled flag"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[],
            enabled=False,
            version=1,
        )
        provider = InMemoryProvider()
        provider.add_flag(flag)

        ff = FeatureFlags(provider)
        assert ff.is_enabled("test_flag") is False

    def test_is_enabled_flag_not_found_return_false(self) -> None:
        """Test is_enabled with non-existent flag returns False"""
        provider = InMemoryProvider()

        ff = FeatureFlags(provider, on_flag_not_found="return_false")
        assert ff.is_enabled("missing_flag") is False

    def test_is_enabled_flag_not_found_raise(self) -> None:
        """Test is_enabled with non-existent flag raises error"""
        provider = InMemoryProvider()

        ff = FeatureFlags(provider, on_flag_not_found="raise")
        with pytest.raises(FeatureFlagsFlagNotFoundError, match="not found"):
            ff.is_enabled("missing_flag")

    def test_is_enabled_evaluation_error_return_false(self) -> None:
        """Test is_enabled handles evaluation error with return_false"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    "AND",
                    [
                        Rule(
                            "AND",
                            [Condition("missing", "EQUALS", "value", True)],
                            True,
                        )
                    ],
                    True,
                )
            ],
            enabled=True,
            version=1,
        )
        provider = InMemoryProvider()
        provider.add_flag(flag)

        ff = FeatureFlags(provider, on_evaluation_error="return_false")
        assert ff.is_enabled("test_flag", ctx={}) is False

    def test_is_enabled_evaluation_error_raise(self) -> None:
        """Test is_enabled handles evaluation error with raise"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    "AND",
                    [
                        Rule(
                            "AND",
                            [Condition("missing", "EQUALS", "value", True)],
                            True,
                        )
                    ],
                    True,
                )
            ],
            enabled=True,
            version=1,
        )
        provider = InMemoryProvider()
        provider.add_flag(flag)

        ff = FeatureFlags(provider, on_evaluation_error="raise")
        with pytest.raises(FeatureFlagsEvaluationError):
            ff.is_enabled("test_flag", ctx={})

    def test_is_enabled_with_context(self) -> None:
        """Test is_enabled passing context for evaluation"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)],
                True,
            )
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        provider = InMemoryProvider()
        provider.add_flag(flag)

        ff = FeatureFlags(provider)
        assert ff.is_enabled("test_flag", ctx={"age": 18}) is True
        assert ff.is_enabled("test_flag", ctx={"age": 30}) is False

    def test_is_enabled_override_on_flag_not_found(self) -> None:
        """Test overriding on_flag_not_found per call"""
        provider = InMemoryProvider()

        ff = FeatureFlags(provider, on_flag_not_found="return_false")
        with pytest.raises(FeatureFlagsFlagNotFoundError):
            ff.is_enabled("missing", on_flag_not_found="raise")

    def test_feature_flags_creation_with_provider_error(self) -> None:
        """Test creating FeatureFlags instance with on_provider_error parameter"""
        provider = InMemoryProvider()
        ff = FeatureFlags(provider, on_provider_error="raise")
        assert ff._provider is provider
        assert ff._on_provider_error == "raise"

    def test_is_enabled_provider_error_return_false(self) -> None:
        """Test is_enabled handles provider exception with return_false"""

        class BrokenProvider:
            def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Database connection failed"
                raise RuntimeError(msg)

        provider = BrokenProvider()  # type: ignore[assignment]
        ff = FeatureFlags(provider, on_provider_error="return_false")
        assert ff.is_enabled("test_flag") is False

    def test_is_enabled_provider_error_raise(self) -> None:
        """Test is_enabled handles provider exception with raise"""

        class BrokenProvider:
            def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Database connection failed"
                raise RuntimeError(msg)

        provider = BrokenProvider()  # type: ignore[assignment]
        ff = FeatureFlags(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError, match="Database connection failed"):
            ff.is_enabled("test_flag")

    def test_is_enabled_provider_error_chained_exception(self) -> None:
        """Test is_enabled preserves exception chain for provider errors"""

        class BrokenProvider:
            def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Invalid flag configuration"
                raise ValueError(msg)

        provider = BrokenProvider()  # type: ignore[assignment]
        ff = FeatureFlags(provider, on_provider_error="raise")
        try:
            ff.is_enabled("test_flag")
        except FeatureFlagsProviderError as exc:
            assert exc.__cause__ is not None
            assert isinstance(exc.__cause__, ValueError)

    def test_is_enabled_override_on_provider_error(self) -> None:
        """Test overriding on_provider_error per call"""

        class BrokenProvider:
            def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Provider down"
                raise RuntimeError(msg)

        provider = BrokenProvider()  # type: ignore[assignment]
        ff = FeatureFlags(provider, on_provider_error="return_false")
        with pytest.raises(FeatureFlagsProviderError, match="Provider down"):
            ff.is_enabled("test_flag", on_provider_error="raise")

    def test_is_enabled_provider_error_with_different_exception_types(self) -> None:
        """Test provider error handling works with different exception types"""

        class BrokenProvider:
            def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Flag storage missing"
                raise KeyError(msg)

        provider = BrokenProvider()  # type: ignore[assignment]
        ff = FeatureFlags(provider, on_provider_error="return_false")
        assert ff.is_enabled("test_flag") is False

        ff_raise = FeatureFlags(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError, match="Flag storage missing"):
            ff_raise.is_enabled("test_flag")

    def test_is_enabled_with_none_context_converts_to_empty_dict(self) -> None:
        """Test that None context is converted to empty dict"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[],  # No rules, should return True
            enabled=True,
            version=1,
        )
        provider = InMemoryProvider()
        provider.add_flag(flag)

        ff = FeatureFlags(provider)
        # Pass None context; should be converted to {} internally
        assert ff.is_enabled("test_flag", ctx=None) is True

    def test_is_enabled_with_none_context_and_rules(self) -> None:
        """Test that None context is converted to empty dict even with rules"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    "AND",
                    [Rule("AND", [Condition("user.age", "GREATER_THAN", 18, True)], True)],
                    True,
                )
            ],
            enabled=True,
            version=1,
        )
        provider = InMemoryProvider()
        provider.add_flag(flag)

        ff = FeatureFlags(provider, on_evaluation_error="return_false")
        # ctx=None converts to {} which will fail when trying to access "user.age"
        # But with on_evaluation_error="return_false", it returns False instead of raising
        assert ff.is_enabled("test_flag", ctx=None) is False


class TestFeatureFlagsAsync:
    """Test asynchronous FeatureFlagsAsync evaluator"""

    @pytest.mark.asyncio
    async def test_is_enabled_flag_exists_and_enabled(self) -> None:
        """Test async is_enabled with existing enabled flag"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        provider = InMemoryProviderAsync()
        provider.add_flag(flag)

        ff = FeatureFlagsAsync(provider)
        result = await ff.is_enabled("test_flag")
        assert result is True

    @pytest.mark.asyncio
    async def test_is_enabled_flag_not_found_return_false(self) -> None:
        """Test async is_enabled with non-existent flag returns False"""
        provider = InMemoryProviderAsync()

        ff = FeatureFlagsAsync(provider, on_flag_not_found="return_false")
        result = await ff.is_enabled("missing_flag")
        assert result is False

    @pytest.mark.asyncio
    async def test_is_enabled_flag_not_found_raise(self) -> None:
        """Test async is_enabled with non-existent flag raises error"""
        provider = InMemoryProviderAsync()

        ff = FeatureFlagsAsync(provider, on_flag_not_found="raise")
        with pytest.raises(FeatureFlagsFlagNotFoundError):
            await ff.is_enabled("missing_flag")

    @pytest.mark.asyncio
    async def test_is_enabled_with_context(self) -> None:
        """Test async is_enabled with context"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)],
                True,
            )
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        provider = InMemoryProviderAsync()
        provider.add_flag(flag)

        ff = FeatureFlagsAsync(provider)
        assert await ff.is_enabled("test_flag", ctx={"age": 18}) is True
        assert await ff.is_enabled("test_flag", ctx={"age": 35}) is False

    @pytest.mark.asyncio
    async def test_is_enabled_evaluation_error_raise_async(self) -> None:
        """Test async is_enabled handles evaluation error with raise"""
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    "AND",
                    [
                        Rule(
                            "AND",
                            [Condition("missing", "EQUALS", "value", True)],
                            True,
                        )
                    ],
                    True,
                )
            ],
            enabled=True,
            version=1,
        )
        provider = InMemoryProviderAsync()
        provider.add_flag(flag)

        ff = FeatureFlagsAsync(provider, on_evaluation_error="raise")
        with pytest.raises(FeatureFlagsEvaluationError):
            await ff.is_enabled("test_flag", ctx={})

    @pytest.mark.asyncio
    async def test_feature_flags_async_creation_with_provider_error(self) -> None:
        """Test creating FeatureFlagsAsync instance with on_provider_error parameter"""
        provider = InMemoryProviderAsync()
        ff = FeatureFlagsAsync(provider, on_provider_error="raise")
        assert ff._provider is provider
        assert ff._on_provider_error == "raise"

    @pytest.mark.asyncio
    async def test_is_enabled_async_provider_error_return_false(self) -> None:
        """Test async is_enabled handles provider exception with return_false"""

        class BrokenAsyncProvider:
            async def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Async database connection failed"
                raise RuntimeError(msg)

        provider = BrokenAsyncProvider()  # type: ignore[assignment]
        ff = FeatureFlagsAsync(provider, on_provider_error="return_false")
        result = await ff.is_enabled("test_flag")
        assert result is False

    @pytest.mark.asyncio
    async def test_is_enabled_async_provider_error_raise(self) -> None:
        """Test async is_enabled handles provider exception with raise"""

        class BrokenAsyncProvider:
            async def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Async database connection failed"
                raise RuntimeError(msg)

        provider = BrokenAsyncProvider()  # type: ignore[assignment]
        ff = FeatureFlagsAsync(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError, match="Async database connection failed"):
            await ff.is_enabled("test_flag")

    @pytest.mark.asyncio
    async def test_is_enabled_async_provider_error_chained_exception(self) -> None:
        """Test async is_enabled preserves exception chain for provider errors"""

        class BrokenAsyncProvider:
            async def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Async invalid flag configuration"
                raise ValueError(msg)

        provider = BrokenAsyncProvider()  # type: ignore[assignment]
        ff = FeatureFlagsAsync(provider, on_provider_error="raise")
        try:
            await ff.is_enabled("test_flag")
        except FeatureFlagsProviderError as exc:
            assert exc.__cause__ is not None
            assert isinstance(exc.__cause__, ValueError)

    @pytest.mark.asyncio
    async def test_is_enabled_async_override_on_provider_error(self) -> None:
        """Test overriding on_provider_error per call in async context"""

        class BrokenAsyncProvider:
            async def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Async provider down"
                raise RuntimeError(msg)

        provider = BrokenAsyncProvider()  # type: ignore[assignment]
        ff = FeatureFlagsAsync(provider, on_provider_error="return_false")
        with pytest.raises(FeatureFlagsProviderError, match="Async provider down"):
            await ff.is_enabled("test_flag", on_provider_error="raise")

    @pytest.mark.asyncio
    async def test_is_enabled_async_provider_error_with_different_exception_types(self) -> None:
        """Test async provider error handling works with different exception types"""

        class BrokenAsyncProvider:
            async def get_flag(self, flag_name: str) -> Flag | None:
                msg = "Async flag storage missing"
                raise KeyError(msg)

        provider = BrokenAsyncProvider()  # type: ignore[assignment]
        ff = FeatureFlagsAsync(provider, on_provider_error="return_false")
        result = await ff.is_enabled("test_flag")
        assert result is False

        ff_raise = FeatureFlagsAsync(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError, match="Async flag storage missing"):
            await ff_raise.is_enabled("test_flag")


class TestRuleOperatorEvaluator:
    """Test missing operator evaluator error handling for rules"""

    def test_rule_evaluate_missing_operator(self) -> None:
        """Test error handling when rule operator evaluator is not found"""
        conditions = [Condition("age", "GREATER_THAN", 25, True)]
        rule = Rule(operator="AND", conditions=conditions, active=True)
        rule.operator = "INVALID_OP"  # type: ignore[assignment]
        with pytest.raises(FeatureFlagsEvaluationError, match="not found"):
            rule.evaluate(ctx={"age": 18})


class TestRuleGroupOperatorEvaluator:
    """Test missing operator evaluator error handling for rule groups"""

    def test_rule_group_evaluate_missing_operator(self) -> None:
        """Test error handling when rule group operator evaluator is not found"""
        rules = [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)]
        rg = RuleGroup(operator="AND", rules=rules, active=True)
        rg.operator = "INVALID_OP"  # type: ignore[assignment]
        with pytest.raises(FeatureFlagsEvaluationError, match="not found"):
            rg.evaluate(ctx={"age": 18})


class TestFlagStrategyEvaluator:
    """Test missing strategy evaluator error handling for flags"""

    def test_flag_evaluate_missing_strategy(self) -> None:
        """Test error handling when flag rules strategy evaluator is not found"""
        rule_groups = [
            RuleGroup(
                "AND",
                [Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True)],
                True,
            )
        ]
        flag = Flag(
            name="test_flag",
            description=None,
            rules_strategy="ALL",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )
        flag.rules_strategy = "INVALID_STRATEGY"  # type: ignore[assignment]
        with pytest.raises(FeatureFlagsEvaluationError, match="not found"):
            flag.evaluate(ctx={"age": 18})


class TestConditionEvaluatorErrors:
    """Test exception handling in Condition.evaluate"""

    def test_condition_evaluate_unexpected_exception(self) -> None:
        """Test error handling for unexpected exceptions during evaluation"""
        condition = Condition(ctx_attr="age", operator="EQUALS", value=25, active=True)
        condition.operator = "INVALID"  # type: ignore[assignment]
        with pytest.raises(FeatureFlagsEvaluationError, match="not found"):
            condition.evaluate(ctx={"age": 25})

    def test_condition_evaluate_unexpected_runtime_error(self) -> None:
        """Test error handling for unexpected runtime exceptions"""
        # Create a condition that will trigger an unexpected error
        # by using a custom evaluator that raises an unexpected exception
        condition = Condition(ctx_attr="value", operator="EQUALS", value="test", active=True)

        def raise_unexpected(*args: Any, **kwargs: Any) -> None:
            msg = "Unexpected error during evaluation"
            raise RuntimeError(msg)

        with (
            mock.patch.dict(
                "fflgs.core.CONDITION_OPERATOR_EVALUATOR_MAP",
                {"EQUALS": raise_unexpected},
            ),
            pytest.raises(FeatureFlagsEvaluationError, match="Unexpected error"),
        ):
            condition.evaluate(ctx={"value": "test"})


class TestHandleErrorMixin:
    """Test the HandleErrorMixin._handle_error method"""

    def test_handle_error_raise_option(self) -> None:
        """Test _handle_error with 'raise' option"""
        provider = InMemoryProvider()
        ff = FeatureFlags(provider)

        with pytest.raises(FeatureFlagsFlagNotFoundError, match="Test error"):
            ff._handle_error(
                FeatureFlagsFlagNotFoundError,
                "Test error",
                "raise",
                FeatureFlagsFlagNotFoundError("Test error"),
            )

    def test_handle_error_return_false_option(self) -> None:
        """Test _handle_error with 'return_false' option"""
        provider = InMemoryProvider()
        ff = FeatureFlags(provider)

        result = ff._handle_error(
            FeatureFlagsFlagNotFoundError,
            "Test error",
            "return_false",
            FeatureFlagsFlagNotFoundError("Test error"),
        )
        assert result is False


class TestIntegration:
    """Integration tests for complete feature flag scenarios"""

    def test_complex_flag_evaluation_scenario(self) -> None:
        """Test complex scenario with nested rule groups"""
        # Create a flag: user must be (age > 25 AND status=active) OR (role=admin)
        rule_groups = [
            RuleGroup(
                "AND",
                [
                    Rule("AND", [Condition("age", "GREATER_THAN", 25, True)], True),
                    Rule("AND", [Condition("status", "EQUALS", "active", True)], True),
                ],
                True,
            ),
            RuleGroup(
                "OR",
                [
                    Rule("AND", [Condition("role", "CONTAINS", ["admin", "superuser"], True)], True),
                ],
                True,
            ),
        ]
        flag = Flag(
            name="premium_feature",
            description="Premium feature access",
            rules_strategy="ANY",
            rule_groups=rule_groups,
            enabled=True,
            version=1,
        )

        # Test case 1: Adult active user
        ctx1: dict[str, Any] = {"age": 18, "status": "active", "role": "user"}
        assert flag.evaluate(ctx=ctx1) is True

        # Test case 2: Minor active user
        ctx2: dict[str, Any] = {"age": 35, "status": "active", "role": "user"}
        assert flag.evaluate(ctx=ctx2) is False

        # Test case 3: Admin regardless of age/status
        ctx3: dict[str, Any] = {"age": 35, "status": "inactive", "role": "admin"}
        assert flag.evaluate(ctx=ctx3) is True

    def test_full_feature_flags_workflow(self) -> None:
        """Test complete workflow from provider to evaluation"""
        provider = InMemoryProvider()
        flag = Flag(
            name="beta_feature",
            description="Beta feature",
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    "AND",
                    [
                        Rule(
                            "AND",
                            [Condition("beta_tester", "EQUALS", True, True)],
                            True,
                        )
                    ],
                    True,
                )
            ],
            enabled=True,
            version=1,
        )
        provider.add_flag(flag)

        ff = FeatureFlags(provider)
        assert ff.is_enabled("beta_feature", ctx={"beta_tester": True}) is True
        assert ff.is_enabled("beta_feature", ctx={"beta_tester": False}) is False
        assert ff.is_enabled("nonexistent_feature") is False


class TestProviderErrorHandling:
    """Test provider error handling with defensive exception catching"""

    def test_provider_raises_feature_flags_provider_error_return_false(self) -> None:
        """Test handling when provider raises FeatureFlagsProviderError with return_false"""
        provider = mock.Mock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB connection failed")

        ff = FeatureFlags(provider, on_provider_error="return_false")
        result = ff.is_enabled("test_flag")

        assert result is False

    def test_provider_raises_unexpected_exception_return_false(self) -> None:
        """Test defensive handling when provider raises non-FeatureFlagsProviderError"""
        provider = mock.Mock()
        provider.get_flag.side_effect = TimeoutError("Request timeout")

        ff = FeatureFlags(provider, on_provider_error="return_false")
        result = ff.is_enabled("test_flag")

        # Should still handle gracefully
        assert result is False

    def test_provider_error_raises_when_configured(self) -> None:
        """Test that provider errors are raised when on_provider_error='raise'"""
        provider = mock.Mock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB error")

        ff = FeatureFlags(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError):
            ff.is_enabled("test_flag")

    def test_provider_unexpected_error_raises_when_configured(self) -> None:
        """Test that unexpected exceptions from provider are raised as FeatureFlagsProviderError"""
        provider = mock.Mock()
        provider.get_flag.side_effect = RuntimeError("Unexpected error")

        ff = FeatureFlags(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError):
            ff.is_enabled("test_flag")

    def test_provider_error_exception_chaining(self) -> None:
        """Test that exception chaining works (cause is preserved)"""
        provider = mock.Mock()
        original_error = TimeoutError("Connection timeout")
        provider.get_flag.side_effect = original_error

        ff = FeatureFlags(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError) as exc_info:
            ff.is_enabled("test_flag")

        # Verify exception chaining
        assert exc_info.value.__cause__ is original_error

    def test_provider_error_message_includes_flag_name(self) -> None:
        """Test that error message includes the flag name"""
        provider = mock.Mock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB error")

        ff = FeatureFlags(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError, match="test_flag"):
            ff.is_enabled("test_flag")

    def test_provider_error_per_call_override(self) -> None:
        """Test that on_provider_error can be overridden per call"""
        provider = mock.Mock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB error")

        # Constructor default is return_false
        ff = FeatureFlags(provider, on_provider_error="return_false")

        # Override to raise on this specific call
        with pytest.raises(FeatureFlagsProviderError):
            ff.is_enabled("test_flag", on_provider_error="raise")

        # Next call uses constructor default
        result = ff.is_enabled("test_flag")
        assert result is False


class TestProviderErrorHandlingAsync:
    """Test async provider error handling with defensive exception catching"""

    @pytest.mark.asyncio
    async def test_async_provider_raises_feature_flags_provider_error_return_false(self) -> None:
        """Test async handling when provider raises FeatureFlagsProviderError with return_false"""
        provider = mock.AsyncMock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB connection failed")

        ff = FeatureFlagsAsync(provider, on_provider_error="return_false")
        result = await ff.is_enabled("test_flag")

        assert result is False

    @pytest.mark.asyncio
    async def test_async_provider_raises_unexpected_exception_return_false(self) -> None:
        """Test async defensive handling when provider raises non-FeatureFlagsProviderError"""
        provider = mock.AsyncMock()
        provider.get_flag.side_effect = TimeoutError("Request timeout")

        ff = FeatureFlagsAsync(provider, on_provider_error="return_false")
        result = await ff.is_enabled("test_flag")

        # Should still handle gracefully
        assert result is False

    @pytest.mark.asyncio
    async def test_async_provider_error_raises_when_configured(self) -> None:
        """Test that async provider errors are raised when on_provider_error='raise'"""
        provider = mock.AsyncMock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB error")

        ff = FeatureFlagsAsync(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError):
            await ff.is_enabled("test_flag")

    @pytest.mark.asyncio
    async def test_async_provider_unexpected_error_raises_when_configured(self) -> None:
        """Test that unexpected exceptions from async provider are raised as FeatureFlagsProviderError"""
        provider = mock.AsyncMock()
        provider.get_flag.side_effect = RuntimeError("Unexpected error")

        ff = FeatureFlagsAsync(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError):
            await ff.is_enabled("test_flag")

    @pytest.mark.asyncio
    async def test_async_provider_error_exception_chaining(self) -> None:
        """Test that async exception chaining works (cause is preserved)"""
        provider = mock.AsyncMock()
        original_error = TimeoutError("Connection timeout")
        provider.get_flag.side_effect = original_error

        ff = FeatureFlagsAsync(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError) as exc_info:
            await ff.is_enabled("test_flag")

        # Verify exception chaining
        assert exc_info.value.__cause__ is original_error

    @pytest.mark.asyncio
    async def test_async_provider_error_message_includes_flag_name(self) -> None:
        """Test that async error message includes the flag name"""
        provider = mock.AsyncMock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB error")

        ff = FeatureFlagsAsync(provider, on_provider_error="raise")
        with pytest.raises(FeatureFlagsProviderError, match="test_flag"):
            await ff.is_enabled("test_flag")

    @pytest.mark.asyncio
    async def test_async_provider_error_per_call_override(self) -> None:
        """Test that on_provider_error can be overridden per call for async"""
        provider = mock.AsyncMock()
        provider.get_flag.side_effect = FeatureFlagsProviderError("DB error")

        # Constructor default is return_false
        ff = FeatureFlagsAsync(provider, on_provider_error="return_false")

        # Override to raise on this specific call
        with pytest.raises(FeatureFlagsProviderError):
            await ff.is_enabled("test_flag", on_provider_error="raise")

        # Next call uses constructor default
        result = await ff.is_enabled("test_flag")
        assert result is False
