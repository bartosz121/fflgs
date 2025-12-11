import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def generate_cache_key(flag_name: str, version: int, ctx: dict[str, Any] | None) -> str:
    """Generate a deterministic cache key from flag name, version, and context

    Args:
        flag_name: Name of the feature flag
        version: Flag version (required, ensures cache invalidation on flag updates)
        ctx: Context dictionary used for evaluation

    Returns:
        Cache key in format "flag_name:version:ctx_hash"
    """
    ctx_str = json.dumps(ctx or {}, sort_keys=True, default=str)
    ctx_hash = hashlib.sha256(ctx_str.encode()).hexdigest()[:16]  # TODO: risky to trim?

    key = f"{flag_name}:{version}:{ctx_hash}"

    logger.debug(
        "Generated cache key %r for flag %r (version=%d) with context hash",
        key,
        flag_name,
        version,
    )
    return key
