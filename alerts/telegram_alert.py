"""
Telegram Alert Module
Sends real-time threat notifications via Telegram
"""

from typing import Dict, Any
import asyncio
from telegram import Bot
from telegram.error import TelegramError
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_telegram_alert(
    result: Dict[str, Any],
    mitre_ttp: str,
    vol_artifacts: str,
    plot_path: str,
    bot_token: str,
    chat_id: str
) -> bool:
    """
    Send Telegram alert with detection results and visualization
    
    Args:
        result: Detection result dictionary
        mitre_ttp: MITRE TTP string
        vol_artifacts: Volatility artifacts string
        plot_path: Path to PNG visualization
        bot_token: Telegram bot token
        chat_id: Telegram chat ID
    
    Returns:
        True if sent successfully, False otherwise
    """
    try:
        # Build message
        message = format_alert_message(result, mitre_ttp, vol_artifacts)
        
        # Run async sending
        success = asyncio.run(_send_async(bot_token, chat_id, message, plot_path))
        
        if success:
            logger.info("Telegram alert sent successfully")
            return True
        else:
            logger.warning("Telegram alert failed to send")
            return False
            
    except Exception as e:
        logger.error(f"Error sending Telegram alert: {e}")
        return False

async def _send_async(bot_token: str, chat_id: str, message: str, plot_path: str) -> bool:
    """
    Async function to send message and photo to Telegram
    
    Args:
        bot_token: Bot token
        chat_id: Chat ID
        message: Message text
        plot_path: Path to image file
    
    Returns:
        True if successful
    """
    try:
        bot = Bot(token=bot_token)
        
        # Send text message
        await bot.send_message(chat_id=chat_id, text=message, parse_mode='HTML')
        
        # Send visualization
        with open(plot_path, 'rb') as photo:
            await bot.send_photo(
                chat_id=chat_id,
                photo=photo,
                caption="ThreatFade Detection Visualization"
            )
        
        return True
        
    except TelegramError as e:
        logger.error(f"Telegram API error: {e}")
        return False
    except Exception as e:
        logger.error(f"Error in async send: {e}")
        return False

def format_alert_message(result: Dict[str, Any], mitre_ttp: str, vol_artifacts: str) -> str:
    """
    Format alert message for Telegram
    
    Args:
        result: Detection result
        mitre_ttp: MITRE TTP
        vol_artifacts: Volatility artifacts
    
    Returns:
        Formatted message string
    """
    message = "<b>🚨 ThreatFade Alert 🚨</b>\n\n"
    
    message += f"<b>Status:</b> {'THREAT DETECTED' if result['detected'] else 'NORMAL'}\n"
    message += f"<b>Detection Score:</b> {result['score']:.2f}/1.0\n\n"
    
    message += "<b>Metrics:</b>\n"
    message += f"  • Entropy: {result['entropy']:.4f}\n"
    message += f"  • Drop Ratio: {result['drop_ratio']:.4f}\n"
    message += f"  • Z-Score: {result['z_outlier']:.2f}\n\n"
    
    message += "<b>MITRE ATT&CK:</b>\n"
    message += f"  {mitre_ttp}\n\n"
    
    message += "<b>Memory Artifacts:</b>\n"
    message += f"  {vol_artifacts}\n\n"
    
    message += "<i>ThreatFade MVP – Tinlance Limited</i>"
    
    return message

def send_simple_alert(bot_token: str, chat_id: str, alert_text: str) -> bool:
    """
    Send simple text alert (without image)
    
    Args:
        bot_token: Telegram bot token
        chat_id: Telegram chat ID
        alert_text: Alert message
    
    Returns:
        True if successful
    """
    try:
        asyncio.run(_send_simple_async(bot_token, chat_id, alert_text))
        return True
    except Exception as e:
        logger.error(f"Error sending simple alert: {e}")
        return False

async def _send_simple_async(bot_token: str, chat_id: str, alert_text: str) -> bool:
    """
    Async function to send simple text message
    """
    try:
        bot = Bot(token=bot_token)
        await bot.send_message(chat_id=chat_id, text=alert_text, parse_mode='HTML')
        return True
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return False
