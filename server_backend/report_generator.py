
from fpdf import FPDF
from datetime import datetime
import os

class ReportGenerator(FPDF):
    def header(self):
        # Logo could go here if we had one
        # self.image('logo.png', 10, 8, 33)
        self.set_font('Arial', 'B', 15)
        self.cell(80)  # Move to right
        self.cell(30, 10, 'Sentinel Incident Response Report', 0, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - CONFIDENTIAL', 0, 0, 'C')

    def chapter_title(self, label):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, f'{label}', 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, text):
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 5, text)
        self.ln()

    def generate_incident_report(self, incident_data):
        self.alias_nb_pages()
        self.add_page()
        
        # Executive Summary
        self.chapter_title('Executive Summary')
        summary = (
            f"Incident ID: {incident_data.get('id', 'N/A')}\n"
            f"Date: {incident_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
            f"Severity: {incident_data.get('severity', 'Unknown')}\n"
            f"Type: {incident_data.get('type', 'Unknown')}\n"
            f"Status: {incident_data.get('status', 'Active')}\n"
        )
        self.chapter_body(summary)
        
        # Incident Details
        self.chapter_title('Incident Details')
        details = (
            f"Target System: {incident_data.get('target', 'Unknown')}\n"
            f"Source IP: {incident_data.get('ip', 'Unknown')}\n"
            f"Rule Triggered: {incident_data.get('rule', 'Unknown')}\n"
        )
        if 'geo_country' in incident_data:
             details += f"Origin: {incident_data.get('geo_city', '')}, {incident_data.get('geo_country', '')}\n"
        
        self.chapter_body(details)
        
        # Technical Context
        self.chapter_title('Technical Context')
        tech_context = ""
        system_context = incident_data.get('system_context', {})
        
        # If system_context is a string (e.g. error message), just print it
        if isinstance(system_context, str):
             tech_context += f"System Context: {system_context}\n"
        elif isinstance(system_context, dict):
            # Try to extract readable info
            if 'system_info' in system_context:
                sys_info = system_context['system_info']
                if 'os' in sys_info:
                    tech_context += f"OS: {sys_info['os'].get('system')} {sys_info['os'].get('release')}\n"
                if 'cpu' in sys_info:
                    tech_context += f"CPU Load: {sys_info['cpu'].get('cpu_percent')}%\n"
            
            if 'top_processes' in system_context:
                 tech_context += f"Top Processes Count: {len(system_context['top_processes'])}\n"

        if not tech_context:
            tech_context = "No detailed system context available."
            
        self.chapter_body(tech_context)
        
        # Mitigation & Response
        self.chapter_title('Mitigation & Response')
        mitigation = (
            "Automated Actions:\n"
            "- Incident logged to database.\n"
            "- Administrators notified (Desktop Alert/Log).\n"
        )
        
        if incident_data.get('severity') in ['High', 'Critical']:
             mitigation += "- Containment measures (IP Block/Process Kill) initiated.\n"
             
        self.chapter_body(mitigation)

        # Output to file in reports directory
        reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        filename = f"incident_report_{incident_data.get('id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(reports_dir, filename)
        self.output(filepath)
        return filepath, filename
