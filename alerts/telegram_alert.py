"""
Telegram Alert Module
Sends real-time threat notifications via Telegram
"""

from typing import Dict, Any
import asyncio
import logging

try:
    from telegram import Bot
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    Bot = None

try:
    from telegram.error import TelegramError
except ImportError:
    TelegramError = Exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def send_telegram_alert(
    detection_result: Dict[str, Any],
    bot_token: str,
    chat_id: str,
    image_path: str = None
) -> bool:
    """
    Send a detection alert via Telegram.
    
    Args:
        detection_result: The fade detection result dictionary
        bot_token: Telegram bot API token
        chat_id: Target chat ID
        image_path: Optional path to visualization image
        
    Returns:
        bool: True if message sent successfully
    """
    if not TELEGRAM_AVAILABLE:
        logger.info("Telegram alerts skipped — python-telegram-bot not installed")
        return False
    
    try:
        bot = Bot(token=bot_token)
        
        message = (
            f"🚨 *ThreatFade Alert* 🚨\n\n"
            f"• Detected: {'YES' if detection_result.get('detected') else 'NO'}\n"
            f"• Confidence: {detection_result.get('confidence', 'N/A')}\n"
            f"• Score: {detection_result.get('score', 0):.4f}\n"
            f"• MITRE TTP: {detection_result.get('mitre_ttp', 'N/A')}\n"
            f"• Z-Outlier: {detection_result.get('z_outlier', 0):.2f}\n"
            f"• Drop Ratio: {detection_result.get('drop_ratio', 0):.2f}\n\n"
            f"_ThreatFade v0.3.0-beta — Tinlance Limited_"
        )
        
        if image_path:
            with open(image_path, 'rb') as img:
                await bot.send_photo(
                    chat_id=chat_id,
                    photo=img,
                    caption=message,
                    parse_mode='Markdown'
                )
        else:
            await bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode='Markdown'
            )
        
        logger.info("Telegram alert sent successfully")
        return True
        
    except TelegramError as e:
        logger.error(f"Telegram API error: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")
        return False


def send_alert_sync(
    detection_result: Dict[str, Any],
    bot_token: str,
    chat_id: str,
    image_path: str = None
) -> bool:
    """Synchronous wrapper for send_telegram_alert."""
    try:
        return asyncio.run(send_telegram_alert(
            detection_result, bot_token, chat_id, image_path
        ))
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        return False
