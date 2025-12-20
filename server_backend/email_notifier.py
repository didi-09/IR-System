"""
Email notification module for security incidents.
Sends email alerts for high-priority incidents.
"""
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Optional

class EmailNotifier:
    """Email notification handler."""
    
    def __init__(
        self,
        smtp_server: Optional[str] = None,
        smtp_port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_email: Optional[str] = None,
        to_email: Optional[str] = None
    ):
        """
        Initialize email notifier.
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP port (usually 587 for TLS)
            username: SMTP username
            password: SMTP password/app password
            from_email: From email address
            to_email: To email address (can be comma-separated)
        """
        self.smtp_server = smtp_server or os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = smtp_port or int(os.getenv('SMTP_PORT', '587'))
        self.username = username or os.getenv('SMTP_USERNAME')
        self.password = password or os.getenv('SMTP_PASSWORD')
        self.from_email = from_email or os.getenv('SMTP_FROM', self.username)
        self.to_email = to_email or os.getenv('SMTP_TO')
        
        self.enabled = all([self.smtp_server, self.username, self.password, self.to_email])
        
        if not self.enabled:
            print("⚠️  Email notifications disabled - missing configuration")
    
    def send_incident_alert(self, incident: Dict) -> bool:
        """
        Send email alert for an incident.
        
        Args:
            incident: Incident dictionary
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            print("[EMAIL] Not configured, skipping email notification")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 Security Alert: {incident.get('type')} - {incident.get('severity')}"
            msg['From'] = self.from_email
            msg['To'] = self.to_email
            
            # Create HTML body
            html_body = self._create_html_body(incident)
            
            # Create plain text body
            text_body = self._create_text_body(incident)
            
            # Attach both versions
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            print(f"✅ [EMAIL] Alert sent to {self.to_email}")
            return True
            
        except Exception as e:
            print(f"❌ [EMAIL] Failed to send alert: {e}")
            return False
    
    def _create_text_body(self, incident: Dict) -> str:
        """Create plain text email body."""
        return f"""
SECURITY INCIDENT DETECTED

Severity: {incident.get('severity')}
Type: {incident.get('type')}
Source IP: {incident.get('ip')}
Target: {incident.get('target')}
Rule: {incident.get('rule')}
Time: {incident.get('timestamp')}

Geographic Information:
- Country: {incident.get('geo_country', 'Unknown')}
- City: {incident.get('geo_city', 'Unknown')}
- ISP: {incident.get('geo_isp', 'Unknown')}

Threat Intelligence:
- Risk Level: {incident.get('threat_risk_level', 'Unknown')}
- Risk Score: {incident.get('threat_risk_score', 'N/A')}
- Abuse Reports: {incident.get('abuse_total_reports', 'N/A')}

Action Required:
Please review this incident in the Security Dashboard immediately.

---
This is an automated alert from the IR System.
"""
    
    def _create_html_body(self, incident: Dict) -> str:
        """Create HTML email body."""
        severity = incident.get('severity', 'Unknown')
        severity_color = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745'
        }.get(severity, '#6c757d')
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {severity_color}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
        .content {{ background: #f8f9fa; padding: 20px; border-radius: 0 0 5px 5px; }}
        .field {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #555; }}
        .value {{ color: #000; }}
        .section {{ margin: 20px 0; padding: 15px; background: white; border-left: 4px solid {severity_color}; }}
        .footer {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Security Incident Alert</h1>
            <h2>{incident.get('type')} - {severity}</h2>
        </div>
        <div class="content">
            <div class="section">
                <h3>Incident Details</h3>
                <div class="field">
                    <span class="label">Source IP:</span>
                    <span class="value">{incident.get('ip')}</span>
                </div>
                <div class="field">
                    <span class="label">Target:</span>
                    <span class="value">{incident.get('target')}</span>
                </div>
                <div class="field">
                    <span class="label">Rule Triggered:</span>
                    <span class="value">{incident.get('rule')}</span>
                </div>
                <div class="field">
                    <span class="label">Timestamp:</span>
                    <span class="value">{incident.get('timestamp')}</span>
                </div>
            </div>
            
            <div class="section">
                <h3>Geographic Information</h3>
                <div class="field">
                    <span class="label">Country:</span>
                    <span class="value">{incident.get('geo_country', 'Unknown')}</span>
                </div>
                <div class="field">
                    <span class="label">City:</span>
                    <span class="value">{incident.get('geo_city', 'Unknown')}</span>
                </div>
                <div class="field">
                    <span class="label">ISP:</span>
                    <span class="value">{incident.get('geo_isp', 'Unknown')}</span>
                </div>
            </div>
            
            <div class="section">
                <h3>Threat Intelligence</h3>
                <div class="field">
                    <span class="label">Risk Level:</span>
                    <span class="value" style="color: {severity_color}; font-weight: bold;">
                        {incident.get('threat_risk_level', 'Unknown')}
                    </span>
                </div>
                <div class="field">
                    <span class="label">Risk Score:</span>
                    <span class="value">{incident.get('threat_risk_score', 'N/A')}/100</span>
                </div>
                <div class="field">
                    <span class="label">Abuse Reports:</span>
                    <span class="value">{incident.get('abuse_total_reports', 'N/A')}</span>
                </div>
            </div>
            
            <div class="footer">
                <p><strong>Action Required:</strong> Please review this incident in the Security Dashboard immediately.</p>
                <p>This is an automated alert from the IR System.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""


def get_email_notifier() -> EmailNotifier:
    """Get configured email notifier instance."""
    return EmailNotifier()


if __name__ == '__main__':
    # Test the module
    notifier = get_email_notifier()
    
    if notifier.enabled:
        test_incident = {
            'type': 'Brute Force',
            'severity': 'High',
            'ip': '1.2.3.4',
            'target': 'root',
            'rule': 'Failed Login Count Exceeded',
            'timestamp': datetime.now().isoformat(),
            'geo_country': 'United States',
            'geo_city': 'New York',
            'geo_isp': 'Example ISP',
            'threat_risk_level': 'High',
            'threat_risk_score': 75,
            'abuse_total_reports': 42
        }
        
        print("Sending test email...")
        success = notifier.send_incident_alert(test_incident)
        if success:
            print("✅ Test email sent successfully!")
        else:
            print("❌ Failed to send test email")
    else:
        print("❌ Email notifier not configured")
        print("   Set SMTP_* environment variables in .env file")
