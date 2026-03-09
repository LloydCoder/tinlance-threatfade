"""
Signal Generator
Simulates multi-scenario threat fade patterns for testing
"""

import numpy as np
from typing import Tuple, List

def generate_c2_quieting(points: int = 100) -> Tuple[List[float], List[float]]:
    """
    C2 Command & Control Quieting
    Attackers silence C2 beacon to avoid detection
    
    Pattern: Normal activity → sudden quiet period → slow resume
    """
    timestamps = list(range(points))
    values = []
    
    for i in range(points):
        if i < 20:
            # Normal baseline
            values.append(0.7 + np.random.normal(0, 0.05))
        elif i < 60:
            # Quieting period (low signal)
            values.append(0.15 + np.random.normal(0, 0.03))
        else:
            # Slow recovery
            recovery_factor = (i - 60) / (points - 60)
            values.append(0.15 + (0.5 * recovery_factor) + np.random.normal(0, 0.03))
    
    return timestamps, values

def generate_lotl_gradual(points: int = 100) -> Tuple[List[float], List[float]]:
    """
    Living-Off-The-Land (LOTL) Attack
    Attacker uses native OS tools, causing gradual signal reduction
    
    Pattern: Baseline → gradual drop → near-zero → slight noise
    """
    timestamps = list(range(points))
    values = []
    
    for i in range(points):
        # Gradual linear decay with noise
        decay_factor = max(0.0, 1.0 - (i / points))
        baseline = 0.8 * decay_factor
        noise = np.random.normal(0, 0.04)
        values.append(max(0.0, baseline + noise))
    
    return timestamps, values

def generate_gnss_jamming(points: int = 100) -> Tuple[List[float], List[float]]:
    """
    GNSS Jamming (Cyber-Physical)
    GPS/satellite signals jammed, causing sharp drop in location accuracy signals
    
    Pattern: Stable → sudden drop → noise floor → potential recovery
    """
    timestamps = list(range(points))
    values = []
    
    for i in range(points):
        if i < 25:
            # Normal GPS signal strength
            values.append(0.85 + np.random.normal(0, 0.05))
        elif i < 75:
            # Jamming active (noise floor)
            values.append(0.1 + np.random.uniform(0, 0.15))
        else:
            # Post-jamming (signal recovery)
            values.append(0.6 + np.random.normal(0, 0.08))
    
    return timestamps, values

def generate_normal_with_fake_fade(points: int = 100) -> Tuple[List[float], List[float]]:
    """
    False Positive Scenario
    Normal network activity with brief dip (not evasion)
    
    Pattern: Stable → temporary dip → return to normal (not sustained)
    """
    timestamps = list(range(points))
    values = []
    
    for i in range(points):
        if 40 < i < 50:
            # Brief dip (normal variance, not evasion)
            values.append(0.4 + np.random.normal(0, 0.08))
        else:
            # Normal activity
            values.append(0.75 + np.random.normal(0, 0.05))
    
    return timestamps, values

def generate_mixed_scenario(points: int = 100) -> Tuple[List[float], List[float]]:
    """
    Mixed Scenario
    Combines multiple threat patterns
    """
    timestamps = list(range(points))
    values = []
    
    scenarios = [
        generate_c2_quieting(25),
        generate_lotl_gradual(25),
        generate_gnss_jamming(25),
        generate_normal_with_fake_fade(25)
    ]
    
    for scenario_idx, (_, scenario_values) in enumerate(scenarios):
        values.extend(scenario_values)
    
    return list(range(len(values))), values

def generate_signals(scenario: str = "mixed", points: int = 100) -> Tuple[List[float], List[float]]:
    """
    Generate simulated signals for testing
    
    Args:
        scenario: One of c2_quieting, lotl_gradual, gnss_jam, normal_with_fade, mixed
        points: Number of data points per scenario
    
    Returns:
        Tuple of (timestamps, values)
    """
    if scenario == "c2_quieting":
        return generate_c2_quieting(points)
    elif scenario == "lotl_gradual":
        return generate_lotl_gradual(points)
    elif scenario == "gnss_jam":
        return generate_gnss_jamming(points)
    elif scenario == "normal_with_fade":
        return generate_normal_with_fake_fade(points)
    elif scenario == "mixed":
        return generate_mixed_scenario(points)
    else:
        return generate_mixed_scenario(points)
