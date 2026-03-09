"""
Timeline Visualization
Generates dark-mode cyberpunk PNG visualization of signal and detection
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from typing import Dict, List, Any
from datetime import datetime
import os

def save_plot(
    timestamps: List[float],
    values: List[float],
    result: Dict[str, Any],
    scenario: str
) -> str:
    """
    Generate and save dark-mode PNG visualization
    
    Args:
        timestamps: List of timestamps
        values: List of signal values
        result: Detection result dictionary
        scenario: Scenario name
    
    Returns:
        Path to saved PNG file
    """
    # Ensure reports folder exists
    os.makedirs("reports", exist_ok=True)
    
    # Create figure with dark background
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(14, 6))
    fig.patch.set_facecolor('#0a0e27')
    ax.set_facecolor('#0a0e27')
    
    # Plot main signal
    ax.plot(timestamps, values, color='#00ff88', linewidth=2.5, label='Signal Strength', alpha=0.9)
    ax.fill_between(timestamps, values, alpha=0.15, color='#00ff88')
    
    # Mark fade region if detected
    if result["detected"]:
        fade_start = result.get("fade_start", 0)
        if fade_start >= 0:
            ax.axvline(x=fade_start, color='#ff1744', linestyle='--', linewidth=2, alpha=0.7, label='Fade Start')
            ax.axvspan(fade_start, len(timestamps)-1, alpha=0.1, color='#ff1744')
    
    # Styling
    ax.set_xlabel('Time (samples)', color='#b0bec5', fontsize=12, fontweight='bold')
    ax.set_ylabel('Signal Value', color='#b0bec5', fontsize=12, fontweight='bold')
    
    title_color = '#ff1744' if result["detected"] else '#00ff88'
    title_text = f'ThreatFade Detection – {scenario.upper()}'
    if result["detected"]:
        title_text += f' (Score: {result["score"]:.2f})'
    
    ax.set_title(title_text, color=title_color, fontsize=14, fontweight='bold', pad=20)
    
    # Grid
    ax.grid(True, color='#1a237e', alpha=0.2, linestyle='--')
    ax.set_axisbelow(True)
    
    # Legend
    ax.legend(loc='upper right', framealpha=0.95, facecolor='#0a0e27', edgecolor='#00ff88')
    
    # Tick colors
    ax.tick_params(colors='#b0bec5')
    ax.spines['bottom'].set_color('#b0bec5')
    ax.spines['left'].set_color('#b0bec5')
    ax.spines['right'].set_visible(False)
    ax.spines['top'].set_visible(False)
    
    # Add detection info text box
    info_text = f"Detection: {'YES' if result['detected'] else 'NO'}\n"
    info_text += f"Entropy: {result['entropy']:.3f}\n"
    info_text += f"Drop Ratio: {result['drop_ratio']:.3f}\n"
    info_text += f"Z-Score: {result['z_outlier']:.2f}"
    
    props = dict(boxstyle='round', facecolor='#0d1b2a', edgecolor='#00ff88', alpha=0.9)
    ax.text(
        0.02, 0.98, info_text,
        transform=ax.transAxes,
        fontsize=10,
        verticalalignment='top',
        bbox=props,
        family='monospace',
        color='#00ff88'
    )
    
    # Save
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"reports/threatfade_{scenario}_{timestamp}.png"
    plt.savefig(filename, dpi=150, facecolor='#0a0e27', edgecolor='none', bbox_inches='tight')
    plt.close()
    
    return filename
