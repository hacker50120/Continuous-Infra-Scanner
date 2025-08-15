#!/usr/bin/env python3
"""
Slack Notification System
Sends alerts and reports to Slack channels
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import configuration
from config import SLACK_WEBHOOK_URL, NOTIFICATION_ENABLED

class SlackNotifier:
    def __init__(self):
        self.token = SLACK_WEBHOOK_URL  # Use config value directly
        self.channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
        self.client = None
        
        if NOTIFICATION_ENABLED and self.token:
            try:
                self.client = WebClient(token=self.token)
                logging.info("Slack client initialized successfully")
            except Exception as e:
                logging.error(f"Failed to initialize Slack client: {e}")
        else:
            logging.warning("Slack notifications disabled or SLACK_WEBHOOK_URL not set")

    def send_vulnerability_alert(self, scan_results: Dict[str, Any]) -> bool:
        """Send vulnerability scan results to Slack"""
        if not self.client or not NOTIFICATION_ENABLED:
            return False

        try:
            # Create message blocks
            blocks = self._create_vulnerability_blocks(scan_results)
            response = self.client.chat_postMessage(
                channel=self.channel,
                text="🚨 New Vulnerability Scan Results",
                blocks=blocks
            )
            logging.info(f"Vulnerability alert sent to Slack: {response['ts']}")
            return True

        except SlackApiError as e:
            logging.error(f"Slack API error: {e.response['error']}")
            return False
        except Exception as e:
            logging.error(f"Error sending vulnerability alert: {e}")
            return False

    def send_infrastructure_change_alert(self, changes: Dict[str, List[str]]) -> bool:
        """Send infrastructure change alerts to Slack"""
        if not self.client or not NOTIFICATION_ENABLED:
            return False

        try:
            blocks = self._create_change_alert_blocks(changes)
            response = self.client.chat_postMessage(
                channel=self.channel,
                text="⚠️ Infrastructure Changes Detected",
                blocks=blocks
            )
            logging.info(f"Infrastructure change alert sent to Slack: {response['ts']}")
            return True

        except SlackApiError as e:
            logging.error(f"Slack API error: {e.response['error']}")
            return False
        except Exception as e:
            logging.error(f"Error sending infrastructure change alert: {e}")
            return False

    def _create_vulnerability_blocks(self, scan_results: Dict[str, Any]) -> List[Dict]:
        """Create Slack blocks for vulnerability alerts"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 Vulnerability Scan Results",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Target:*\n{scan_results.get('target', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Vulnerabilities:*\n{scan_results.get('total_vulns', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{scan_results.get('summary', {}).get('risk_score', 0)}/100"
                    }
                ]
            }
        ]
        return blocks

    def _create_change_alert_blocks(self, changes: Dict[str, List[str]]) -> List[Dict]:
        """Create Slack blocks for infrastructure change alerts"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "⚠️ Infrastructure Changes",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Changes Detected:*\n{json.dumps(changes, indent=2)}"
                }
            }
        ]
        return blocks

    def send_daily_report(self, stats: Dict[str, Any]) -> bool:
        """Send daily security report to Slack"""
        if not self.client or not NOTIFICATION_ENABLED:
            return False

        try:
            blocks = self._create_daily_report_blocks(stats)
            response = self.client.chat_postMessage(
                channel=self.channel,
                text="📊 Daily Security Report",
                blocks=blocks
            )
            logging.info(f"Daily report sent to Slack: {response['ts']}")
            return True

        except SlackApiError as e:
            logging.error(f"Slack API error: {e.response['error']}")
            return False
        except Exception as e:
            logging.error(f"Error sending daily report: {e}")
            return False

    def _create_daily_report_blocks(self, stats: Dict[str, Any]) -> List[Dict]:
        """Create Slack blocks for daily security report"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "📊 Daily Security Report",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Scans:*\n{stats.get('total_scans', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Alerts:*\n{stats.get('total_alerts', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Target IPs:*\n{stats.get('target_ips', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{stats.get('risk_score', 0)}/100"
                    }
                ]
            }
        ]

        # Add vulnerability breakdown
        vuln_stats = stats.get('vulnerability_breakdown', {})
        if vuln_stats:
            vuln_text = ""
            for severity, count in vuln_stats.items():
                if count > 0:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                    vuln_text += f"{emoji.get(severity, '⚪')} {severity.title()}: {count}\n"

            if vuln_text:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Vulnerabilities Found:*\n{vuln_text}"
                    }
                })

        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Dashboard",
                        "emoji": True
                    },
                    "style": "primary",
                    "url": f"http://localhost:8180/dashboard"
                }
            ]
        })

        return blocks

# Global notifier instance
slack_notifier = SlackNotifier()
