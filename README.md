# fflgs

**Feature flag evaluation** with hierarchical rule-based architecture. Sync/async, type-safe, extensible.

## Motivation

## Features


## Development

For detailed development setup, running tests, code quality checks, and contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Examples

```python
Rule(
    operator="AND",
    conditions=[
        Condition("user.age", "GREATER_THAN", 21, True),
        Condition("user.region", "IN", ["US", "CA"], True),
    ],
    active=True
)
```

```python
Condition("user.id", "REGEX", r"^[0-4]", True)
```

```python
RuleGroup(
    operator="OR",
    rules=[
        Rule(operator="AND", conditions=[Condition("user.beta", "EQUALS", True, True)], active=True),
        Rule(operator="AND", conditions=[Condition("user.role", "EQUALS", "admin", True)], active=True),
    ],
    active=True
)
```

## License

MIT - See LICENSE.txt
