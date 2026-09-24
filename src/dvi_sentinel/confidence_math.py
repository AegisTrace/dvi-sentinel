"""Bounded numerical primitives for conditional local uncertainty estimates (A)."""

import math
import random
from statistics import NormalDist

from dvi_sentinel.scoring import percentile


def wilson_bounds(
    successes: int, total: int, level: float = 0.95
) -> tuple[float | None, float | None]:
    """Two-sided Wilson score interval; a missing denominator has no interval."""
    if (
        type(successes) is not int
        or type(total) is not int
        or not 0 <= successes <= total <= 1_000_000_000
        or isinstance(level, bool)
        or not math.isfinite(level)
        or not 0 < level < 1
    ):
        raise ValueError("DVI-CONFIDENCE-WILSON: require valid counts and confidence level")
    if total == 0:
        return None, None
    z = NormalDist().inv_cdf((1 + level) / 2)
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return (
        0.0 if successes == 0 else max(0.0, center - half),
        1.0 if successes == total else min(1.0, center + half),
    )


def latency_points(values: tuple[float, ...]) -> tuple[float | None, float | None, float | None]:
    if len(values) > 128 or any(
        isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 86_400_000
        for value in values
    ):
        raise ValueError("DVI-CONFIDENCE-LATENCY: require at most 128 finite nonnegative delays")
    return (
        math.fsum(values) / len(values) if values else None,
        percentile(list(values), 0.5),
        percentile(list(values), 0.95),
    )


def bootstrap_latency(
    values: tuple[float, ...], *, seed: int, resamples: int
) -> tuple[tuple[float, ...], tuple[float, ...], tuple[float, ...]]:
    """Empirical IID percentile bootstrap; replicates are not new observations."""
    latency_points(values)
    if (
        type(seed) is not int
        or not 0 <= seed <= 2**63 - 1
        or type(resamples) is not int
        or not 100 <= resamples <= 1000
    ):
        raise ValueError("DVI-CONFIDENCE-BOOTSTRAP: invalid seed or resample budget")
    if len(values) < 2:
        return (), (), ()
    ordered = sorted(values)
    generator = random.Random(seed)
    means, medians, tails = [], [], []
    for _ in range(resamples):
        sample = tuple(ordered[generator.randrange(len(ordered))] for _ in ordered)
        mean, median, tail = latency_points(sample)
        assert mean is not None and median is not None and tail is not None
        means.append(mean)
        medians.append(median)
        tails.append(tail)
    return tuple(means), tuple(medians), tuple(tails)


def paired_difference_bounds(
    recovered: int, lost: int, total: int, level: float = 0.95
) -> tuple[float | None, float | None]:
    """Approximate Bonferroni-Wilson envelope for paired recovery minus loss rates."""
    wilson_bounds(0, total, level)
    if type(recovered) is not int or type(lost) is not int or recovered + lost > total:
        raise ValueError("DVI-CONFIDENCE-EFFECT: incompatible transition counts")
    lower_gain, upper_gain = wilson_bounds(recovered, total, (1 + level) / 2)
    lower_loss, upper_loss = wilson_bounds(lost, total, (1 + level) / 2)
    if lower_gain is None or upper_gain is None or lower_loss is None or upper_loss is None:
        return None, None
    return max(-1.0, lower_gain - upper_loss), min(1.0, upper_gain - lower_loss)
