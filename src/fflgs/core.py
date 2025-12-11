import logging
import operator
import re
from collections.abc import Callable, Container, Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, time
from typing import Any, Literal, TypeGuard, cast

from fflgs.providers.protocol import FeatureFlagsProvider, FeatureFlagsProviderAsync

_regex_cache: dict[str, re.Pattern[str]] = {}

logger = logging.getLogger("fflgs")

ContainerAny = Container[Any]
ContainerValue = Container[Any]
RegexValue = str

ComparableValue = str | int | float | bool | datetime | date | time
ConditionValueType = str | int | float | bool | datetime | date | time | ContainerAny | None
ConditionValueTypeTuple = (str, int, float, bool, datetime, date, time, Container, None.__class__)


# Evaluators use TypeGuard functions to narrow types and eliminate the need for casts


def _is_comparable_condition(val: ConditionValueType) -> TypeGuard[str | int | float | bool | datetime | date | time]:
    """Condition value supports comparison operators (gt, ge, lt, le)"""
    return isinstance(val, (str, int, float, bool, datetime, date, time))


def _is_container(val: Any) -> TypeGuard[Container[Any]]:
    """Value is a container (for in/not_in/contains/not_contains operations)"""
    return isinstance(val, Container)


# Evaluator functions follow this rule:
# The static condition value (`a`) is always the left operand,
# and the dynamic context value (`b``) is always the right operand.
# Every condition is evaluated as: `static_value <operator> context_value`


def _evaluator_eq(a: ConditionValueType, b: Any) -> bool:
    return operator.eq(a, b)


def _evaluator_ne(a: ConditionValueType, b: Any) -> bool:
    return operator.ne(a, b)


def _evaluator_gt(a: ComparableValue, b: ComparableValue) -> bool:
    return operator.gt(a, b)


def _evaluator_ge(a: ComparableValue, b: ComparableValue) -> bool:
    return operator.ge(a, b)


def _evaluator_lt(a: ComparableValue, b: ComparableValue) -> bool:
    return operator.lt(a, b)


def _evaluator_le(a: ComparableValue, b: ComparableValue) -> bool:
    return operator.le(a, b)


def _evaluator_contains(a: ContainerValue, b: Any) -> bool:
    return operator.contains(a, b)


def _evaluator_not_contains(a: ContainerValue, b: Any) -> bool:
    return operator.not_(operator.contains(a, b))


def _evaluator_in(a: ConditionValueType, b: Any) -> bool:
    return operator.contains(b, a)


def _evaluator_not_in(a: ConditionValueType, b: Any) -> bool:
    return operator.not_(operator.contains(b, a))


def _evaluator_regex(a: RegexValue, b: RegexValue) -> bool:
    try:
        if a not in _regex_cache:
            _regex_cache[a] = re.compile(a)
        pattern = _regex_cache[a]
        return bool(pattern.search(b))
    except re.error as exc:
        msg = f"Regex error: {exc!s}"
        raise ValueError(msg) from exc


ConditionOperator = Literal[
    "EQUALS",
    "NOT_EQUALS",
    "GREATER_THAN",
    "GREATER_THAN_OR_EQUALS",
    "LESS_THAN",
    "LESS_THAN_OR_EQUALS",
    "CONTAINS",
    "NOT_CONTAINS",
    "IN",
    "NOT_IN",
    "REGEX",
]


def _validate_condition_value_with_operator(operator: ConditionOperator, value: Any) -> None:
    """
    Validate that value is compatible with operator

    Raises:
        ValueError: If value type is incompatible with operator
    """
    if operator in {"GREATER_THAN", "GREATER_THAN_OR_EQUALS", "LESS_THAN", "LESS_THAN_OR_EQUALS"}:
        if not _is_comparable_condition(value):
            msg = f"Operator {operator!r} requires comparable value, got {type(value)}"
            raise ValueError(msg)
    elif operator in {"CONTAINS", "NOT_CONTAINS"}:
        if not _is_container(value):
            msg = f"Operator {operator!r} requires container value, got {type(value)}"
            raise ValueError(msg)
    elif operator == "REGEX" and not isinstance(value, str):
        msg = f"Operator {operator!r} requires str value, got {type(value)}"
        raise ValueError(msg)


def _validate_context_value_with_operator(operator: ConditionOperator, ctx_value: Any) -> None:
    """
    Validate that context value is compatible with operator

    Used during condition evaluation to ensure the context value type matches operator requirements

    Raises:
        TypeError: If context value type is incompatible with operator
    """
    if operator in {"GREATER_THAN", "GREATER_THAN_OR_EQUALS", "LESS_THAN", "LESS_THAN_OR_EQUALS"}:
        if not _is_comparable_condition(ctx_value):
            msg = f"Operator {operator!r} requires comparable context value, got {type(ctx_value)}"
            raise TypeError(msg)
    elif operator in {"IN", "NOT_IN"}:
        if not _is_container(ctx_value):
            msg = f"Operator {operator!r} requires container context value, got {type(ctx_value)}"
            raise TypeError(msg)
    elif operator == "REGEX" and not isinstance(ctx_value, str):
        msg = f"Operator {operator!r} requires string context value, got {type(ctx_value)}"
        raise TypeError(msg)


# TODO: doable to get rid of `Any` ???
CONDITION_OPERATOR_EVALUATOR_MAP: dict[ConditionOperator, Callable[[Any, Any], bool]] = {
    "EQUALS": _evaluator_eq,
    "NOT_EQUALS": _evaluator_ne,
    "GREATER_THAN": _evaluator_gt,
    "GREATER_THAN_OR_EQUALS": _evaluator_ge,
    "LESS_THAN": _evaluator_lt,
    "LESS_THAN_OR_EQUALS": _evaluator_le,
    "CONTAINS": _evaluator_contains,
    "NOT_CONTAINS": _evaluator_not_contains,
    "IN": _evaluator_in,
    "NOT_IN": _evaluator_not_in,
    "REGEX": _evaluator_regex,
}

RuleOperator = Literal["AND", "OR"]

RULE_OPERATOR_MAP: dict[RuleOperator, Callable[[Iterable[bool]], bool]] = {
    "AND": all,
    "OR": any,
}

FlagRulesStrategy = Literal["ALL", "ANY", "NONE"]

FLAG_RULES_STRATEGY_MAP: dict[FlagRulesStrategy, Callable[[Iterable[bool]], bool]] = {
    "ALL": all,
    "ANY": any,
    "NONE": lambda iter_: not any(iter_),
}


def _get_value_from_ctx(ctx: dict[str, Any], ctx_attr: str) -> ConditionValueType:
    """
    This uses `Any` type annotations and `cast()` for `val` due to the inherently dynamic nature of context traversal

    The final `cast(ConditionValueType, val)` is safe because we validate the result
    with `isinstance(val, ConditionValueTypeTuple)` immediately before returning
    """
    val: Any = ctx
    parts = ctx_attr.split(".")

    for i, part in enumerate(parts):
        try:
            val = cast(Any, val[part]) if isinstance(val, Mapping) else getattr(val, part)
        except (KeyError, AttributeError) as exc:
            path = ".".join(parts[: i + 1])
            msg = f"{path!r} not found in context"
            raise ValueError(msg) from exc

    if not isinstance(val, ConditionValueTypeTuple):
        msg = f"Unexpected type {type(val)} for value of {ctx_attr!s}"
        raise TypeError(msg)

    return cast(ConditionValueType, val)


def _is_bool(val: bool | None) -> TypeGuard[bool]:  # noqa: FBT001
    """
    Typeguard function to be used with builtin `filter` function
    """
    return type(val) is bool


@dataclass
class Condition:
    """Represents a single condition to evaluate against context.

    A condition evaluates whether a `value` matches context value using a specific operator.
    Conditions are inactive when `active=False`, which causes evaluate() to return None instead
    of a boolean result. Inactive conditions are filtered out during rule evaluation.

    Operators:
        - EQUALS/NOT_EQUALS: Direct equality/inequality comparison
        - GREATER_THAN/GREATER_THAN_OR_EQUALS/LESS_THAN/LESS_THAN_OR_EQUALS: Comparison operators.
          Context value must be comparable (str, int, float, bool, datetime, date, time).
        - CONTAINS/NOT_CONTAINS: Check if condition value (container) contains context value.
          Condition value must be a container (list, str, dict, set, etc.).
        - IN/NOT_IN: Check if context value (container) contains condition value.
          Context value must be a container.
        - REGEX: Pattern matching on context value using regex.
          Both condition and context values must be strings.
    """

    ctx_attr: str
    operator: ConditionOperator
    value: ConditionValueType
    active: bool

    def __post_init__(self) -> None:
        """Validate that condition value is appropriate for its operator"""
        _validate_condition_value_with_operator(self.operator, self.value)

    def evaluate(self, *, ctx: dict[str, Any]) -> bool | None:
        if not self.active:
            return None

        fn = CONDITION_OPERATOR_EVALUATOR_MAP.get(self.operator)
        if fn is None:
            msg = f"Evaluator for operator {self.operator!r} not found"
            raise FeatureFlagsEvaluationError(msg)

        try:
            ctx_value = _get_value_from_ctx(ctx, self.ctx_attr)
            _validate_context_value_with_operator(self.operator, ctx_value)

            result = fn(self.value, ctx_value)
            logger.debug(
                "%r with context %r; %r(%r, %r) evaluated to %r",
                self,
                ctx,
                fn.__name__,
                self.value,
                ctx_value,
                result,
            )
            return result
        except (ValueError, TypeError) as exc:
            raise FeatureFlagsEvaluationError(str(exc)) from exc
        except Exception as exc:
            msg = f"Unexpected error: {exc!s}"
            raise FeatureFlagsEvaluationError(msg) from exc


@dataclass
class Rule:
    """Combines multiple conditions using a logical operator.

    A rule evaluates all its conditions and combines them using AND or OR logic.
    Inactive rules (active=False) return None and are filtered out during rule group evaluation.

    Args:
        operator: Logical operator to combine conditions ("AND" or "OR")
            - "AND": All conditions must be True
            - "OR": At least one condition must be True
        conditions: List of Condition objects to evaluate. Must not be empty.
        active: Whether this rule is active. Inactive rules return None and are filtered out.

    Raises:
        FeatureFlagsEvaluationError: If conditions list is empty during evaluation.

    Note:
        When all conditions are inactive, all([]) returns True for AND and any([]) returns False for OR.
        See the active field in Condition for details on inactive condition filtering.
    """

    operator: RuleOperator
    conditions: list[Condition]
    active: bool

    def evaluate(self, *, ctx: dict[str, Any]) -> bool | None:
        if not self.active:
            return None

        if not self.conditions:
            msg = f"No conditions found for {self!r}"
            raise FeatureFlagsEvaluationError(msg)

        rule_result_evaluation_fn = RULE_OPERATOR_MAP.get(self.operator)
        if rule_result_evaluation_fn is None:
            msg = f"Evaluator for rule operator {self.operator!r} not found"
            raise FeatureFlagsEvaluationError(msg)

        bools = tuple(
            filter(
                _is_bool,
                (condition.evaluate(ctx=ctx) for condition in self.conditions),
            )
        )
        logger.debug("%r evaluated conditions to %r", self, bools)
        return rule_result_evaluation_fn(bools)


@dataclass
class RuleGroup:
    """Combines multiple rules using a logical operator.

    A rule group evaluates all its rules and combines them using AND or OR logic.
    Inactive rule groups (active=False) return None and are filtered out during flag evaluation.

    Args:
        operator: Logical operator to combine rules ("AND" or "OR")
            - "AND": All rules must be True
            - "OR": At least one rule must be True
        rules: List of Rule objects to evaluate. Must not be empty.
        active: Whether this rule group is active. Inactive rule groups return None and are filtered out.

    Raises:
        FeatureFlagsEvaluationError: If rules list is empty during evaluation.

    Note:
        When all rules are inactive, all([]) returns True for AND and any([]) returns False for OR.
        See the active field in Rule for details on inactive rule filtering.
    """

    operator: RuleOperator
    rules: list[Rule]
    active: bool

    def evaluate(self, *, ctx: dict[str, Any]) -> bool | None:
        if not self.active:
            return None

        if not self.rules:
            msg = f"No rules found for {self!r}"
            raise FeatureFlagsEvaluationError(msg)

        rule_group_result_evaluation_fn = RULE_OPERATOR_MAP.get(self.operator)
        if rule_group_result_evaluation_fn is None:
            msg = f"Evaluator for rule group {self.operator!r} not found"
            raise FeatureFlagsEvaluationError(msg)

        bools = tuple(
            filter(
                _is_bool,
                (rule.evaluate(ctx=ctx) for rule in self.rules),
            )
        )
        logger.debug("%r evaluated rules to %r", self, bools)
        return rule_group_result_evaluation_fn(bools)


@dataclass
class Flag:
    """Represents a feature flag with rule groups evaluated using a strategy.

    A flag is enabled if enabled=True and the rule groups evaluation succeeds based on the rules_strategy.
    If enabled=False, the flag always returns False regardless of rule groups.
    If there are no rule groups and enabled=True, the flag always returns True.

    Args:
        name: The name of the feature flag.
        description: Optional description of the flag's purpose.
        rules_strategy: Strategy for combining rule group results ("ALL", "ANY", or "NONE")
            - "ALL": All rule groups must evaluate to True (AND logic)
            - "ANY": At least one rule group must evaluate to True (OR logic)
            - "NONE": All rule groups must evaluate to False (NOR logic)
        rule_groups: List of RuleGroup objects that determine flag evaluation.
        enabled: Whether this flag is enabled. If False, always returns False.
        version: Version number of the flag for tracking changes.

    Note:
        When all rule groups are inactive, all([]) returns True for ALL strategy, any([]) returns False
        for ANY strategy, and NONE returns True. This behavior is documented in Rule/RuleGroup.
    """

    name: str
    description: str | None
    rules_strategy: FlagRulesStrategy
    rule_groups: list[RuleGroup]
    enabled: bool
    version: int

    def evaluate(self, *, ctx: dict[str, Any]) -> bool:
        if not self.enabled:
            return False

        if not self.rule_groups:
            return True

        flag_evaluate_fn = FLAG_RULES_STRATEGY_MAP.get(self.rules_strategy)
        if flag_evaluate_fn is None:
            msg = f"Evaluator for flag rules strategy {self.rules_strategy!r} not found"
            raise FeatureFlagsEvaluationError(msg)

        bools = tuple(
            filter(
                _is_bool,
                (rg.evaluate(ctx=ctx) for rg in self.rule_groups),
            )
        )
        logger.debug("%r evaluated rule groups to %r", self, bools)
        return flag_evaluate_fn(bools)


class FeatureFlagsError(Exception): ...


class FeatureFlagsFlagNotFoundError(FeatureFlagsError): ...


class FeatureFlagsEvaluationError(FeatureFlagsError): ...


class FeatureFlagsProviderError(FeatureFlagsError): ...


OnOption = Literal["raise", "return_false"]


class HandleErrorMixin:
    """Mixin for handling errors during flag evaluation with configurable behavior"""

    def _handle_error(  # noqa: PLR6301
        self,
        error_type: type[FeatureFlagsError],
        message: str,
        option: OnOption,
        cause: Exception | None = None,
    ) -> bool:
        """Handle errors during flag evaluation.

        Args:
            error_type: The exception class to raise
            message: Error message
            option: "raise" to re-raise exception, "return_false" to return False
            cause: The original exception that caused the error (for exception chaining)

        Returns:
            False when option is "return_false"

        Raises:
            FeatureFlagsError: When option is "raise"
        """
        if option == "raise":
            logger.error("Re raising caught exception: %s %s", error_type.__name__, message)
            raise error_type(message) from cause
        logger.warning(
            "Ignoring caught exception, flag evaluated to False: %s %s",
            error_type.__name__,
            message,
        )
        return False


class FeatureFlags(HandleErrorMixin):
    """Feature flags evaluator.

    Provides methods to check if feature flags are enabled for a given context.

    Args:
        provider: Feature flags provider implementation
        on_flag_not_found: How to handle missing flags ("raise" or "return_false")
        on_evaluation_error: How to handle evaluation errors ("raise" or "return_false")
        on_provider_error: How to handle provider exceptions ("raise" or "return_false")
    """

    _provider: FeatureFlagsProvider
    _on_flag_not_found: OnOption
    _on_evaluation_error: OnOption
    _on_provider_error: OnOption

    def __init__(
        self,
        provider: FeatureFlagsProvider,
        on_flag_not_found: OnOption = "return_false",
        on_evaluation_error: OnOption = "return_false",
        on_provider_error: OnOption = "return_false",
    ) -> None:
        self._provider = provider
        self._on_flag_not_found = on_flag_not_found
        self._on_evaluation_error = on_evaluation_error
        self._on_provider_error = on_provider_error

    def is_enabled(
        self,
        flag_name: str,
        *,
        ctx: dict[str, Any] | None = None,
        on_flag_not_found: OnOption | None = None,
        on_evaluation_error: OnOption | None = None,
        on_provider_error: OnOption | None = None,
    ) -> bool:
        """Check if a feature flag is enabled.

        Args:
            flag_name: Name of the flag to check
            ctx: Context dictionary for evaluation
            on_flag_not_found: Override constructor setting for missing flags
            on_evaluation_error: Override constructor setting for evaluation errors
            on_provider_error: Override constructor setting for provider exceptions

        Returns:
            True if flag is enabled, False otherwise (depending on error handling configuration)

        Raises:
            FeatureFlagsFlagNotFoundError: If flag not found and on_flag_not_found="raise"
            FeatureFlagsEvaluationError: If evaluation fails and on_evaluation_error="raise"
            FeatureFlagsProviderError: If provider raises and on_provider_error="raise"
        """
        on_flag_not_found = self._on_flag_not_found if on_flag_not_found is None else on_flag_not_found
        logger.debug("on_flag_not_found=%r", on_flag_not_found)
        on_evaluation_error = self._on_evaluation_error if on_evaluation_error is None else on_evaluation_error
        logger.debug("on_evaluation_error=%r", on_evaluation_error)
        on_provider_error = self._on_provider_error if on_provider_error is None else on_provider_error
        logger.debug("on_provider_error=%r", on_provider_error)

        try:
            flag = self._provider.get_flag(flag_name)
        except (FeatureFlagsProviderError, Exception) as exc:
            # Catch both FeatureFlagsProviderError (expected) and other exceptions (defensive fallback).
            # Providers should raise FeatureFlagsProviderError for any errors encountered
            # while fetching flags, but we defensively catch all exceptions to handle
            # misbehaving providers gracefully.
            return self._handle_error(
                FeatureFlagsProviderError,
                f"Provider error retrieving flag {flag_name!r}: {exc!s}",
                on_provider_error,
                cause=exc,
            )

        if flag is None:
            return self._handle_error(
                FeatureFlagsFlagNotFoundError,
                f"Flag {flag_name!r} not found",
                on_flag_not_found,
            )

        try:
            ctx = ctx or {}
            result = flag.evaluate(ctx=ctx)
            logger.info("Flag %r with context %r evaluated to %s", flag.name, ctx, result)
            return result
        except FeatureFlagsEvaluationError as exc:
            return self._handle_error(
                FeatureFlagsEvaluationError,
                str(exc),
                on_evaluation_error,
                cause=exc,
            )


class FeatureFlagsAsync(HandleErrorMixin):
    """Asynchronous feature flags evaluator.

    Provides async methods to check if feature flags are enabled for a given context.

    Args:
        provider: Async feature flags provider implementation
        on_flag_not_found: How to handle missing flags ("raise" or "return_false")
        on_evaluation_error: How to handle evaluation errors ("raise" or "return_false")
        on_provider_error: How to handle provider exceptions ("raise" or "return_false")
    """

    _provider: FeatureFlagsProviderAsync
    _on_flag_not_found: OnOption
    _on_evaluation_error: OnOption
    _on_provider_error: OnOption

    def __init__(
        self,
        provider: FeatureFlagsProviderAsync,
        on_flag_not_found: OnOption = "return_false",
        on_evaluation_error: OnOption = "return_false",
        on_provider_error: OnOption = "return_false",
    ) -> None:
        self._provider = provider
        self._on_flag_not_found = on_flag_not_found
        self._on_evaluation_error = on_evaluation_error
        self._on_provider_error = on_provider_error

    async def is_enabled(
        self,
        flag_name: str,
        *,
        ctx: dict[str, Any] | None = None,
        on_flag_not_found: OnOption | None = None,
        on_evaluation_error: OnOption | None = None,
        on_provider_error: OnOption | None = None,
    ) -> bool:
        """Check if a feature flag is enabled (async).

        Args:
            flag_name: Name of the flag to check
            ctx: Context dictionary for evaluation
            on_flag_not_found: Override constructor setting for missing flags
            on_evaluation_error: Override constructor setting for evaluation errors
            on_provider_error: Override constructor setting for provider exceptions

        Returns:
            True if flag is enabled, False otherwise (depending on error handling configuration)

        Raises:
            FeatureFlagsFlagNotFoundError: If flag not found and on_flag_not_found="raise"
            FeatureFlagsEvaluationError: If evaluation fails and on_evaluation_error="raise"
            FeatureFlagsProviderError: If provider raises and on_provider_error="raise"
        """
        on_flag_not_found = self._on_flag_not_found if on_flag_not_found is None else on_flag_not_found
        logger.debug("on_flag_not_found=%r", on_flag_not_found)
        on_evaluation_error = self._on_evaluation_error if on_evaluation_error is None else on_evaluation_error
        logger.debug("on_evaluation_error=%r", on_evaluation_error)
        on_provider_error = self._on_provider_error if on_provider_error is None else on_provider_error
        logger.debug("on_provider_error=%r", on_provider_error)

        try:
            flag = await self._provider.get_flag(flag_name)
        except (FeatureFlagsProviderError, Exception) as exc:
            # Catch both FeatureFlagsProviderError (expected) and other exceptions (defensive fallback).
            # Providers should raise FeatureFlagsProviderError for any errors encountered
            # while fetching flags, but we defensively catch all exceptions to handle
            # misbehaving providers gracefully.
            return self._handle_error(
                FeatureFlagsProviderError,
                f"Provider error retrieving flag {flag_name!r}: {exc!s}",
                on_provider_error,
                cause=exc,
            )

        if flag is None:
            return self._handle_error(
                FeatureFlagsFlagNotFoundError,
                f"Flag {flag_name!r} not found",
                on_flag_not_found,
            )

        try:
            ctx = ctx or {}
            result = flag.evaluate(ctx=ctx)
            logger.info("Flag %r with context %r evaluated to %s", flag.name, ctx, result)
            return result
        except FeatureFlagsEvaluationError as exc:
            return self._handle_error(
                FeatureFlagsEvaluationError,
                str(exc),
                on_evaluation_error,
                cause=exc,
            )
