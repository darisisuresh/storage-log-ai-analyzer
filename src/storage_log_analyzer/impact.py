"""Optional, explicitly supplied business-impact index; not calibrated risk."""
import math

WEIGHTS = {'impact': .30, 'urgency': .25, 'correlation': .20, 'duration': .15, 'exposure': .10}


def components(value):
    if not isinstance(value, dict) or set(value) != set(WEIGHTS):
        raise ValueError('risk_components requires impact, urgency, correlation, duration and exposure')
    if any(type(v) not in (int, float) or not 0 <= v <= 100 or not math.isfinite(v) for v in value.values()):
        raise ValueError('Each risk component must be a finite number from 0 to 100')
    return {key: float(value[key]) for key in WEIGHTS}


def score(value):
    values = components(value)
    return round(sum(WEIGHTS[key] * values[key] for key in WEIGHTS), 2)
