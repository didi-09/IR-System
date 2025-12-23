#!/usr/bin/env python3
"""
Generate PDF from README using markdown to HTML to PDF conversion.
"""

import markdown
from weasyprint import HTML
from pathlib import Path

def generate_pdf():
    """Convert README.md to PDF."""
    
    readme_path = Path("README.md")
    output_pdf = Path("Sentinel_Project_Documentation.pdf")
    output_html = Path("Sentinel_Project_Documentation.html")
    
    print("📄 Reading README.md...")
    with open(readme_path, 'r') as f:
        md_content = f.read()
    
    print("🔄 Converting Markdown to HTML...")
    html_content = markdown.markdown(
        md_content,
        extensions=['tables', 'fenced_code', 'codehilite']
    )
    
    # Add CSS styling
    styled_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                max-width: 900px;
                margin: 40px auto;
                padding: 20px;
                color: #333;
            }}
            h1 {{ 
                color: #1a237e; 
                border-bottom: 3px solid #3f51b5; 
                padding-bottom: 10px; 
                margin-top: 40px;
            }}
            h2 {{ 
                color: #283593; 
                border-bottom: 2px solid #7986cb; 
                padding-bottom: 8px; 
                margin-top: 30px; 
            }}
            h3 {{ 
                color: #3949ab; 
                margin-top: 20px;
            }}
            code {{
                background-color: #e8eaf6;
                color: #283593;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
            }}
            pre {{
                background-color: #1e1e1e;
                color: #d4d4d4;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                border-left: 4px solid #3f51b5;
            }}
            pre code {{
                background-color: transparent;
                color: #d4d4d4;
                padding: 0;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin: 20px 0;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            th, td {{
                border: 1px solid #c5cae9;
                padding: 12px;
                text-align: left;
            }}
            th {{
                background-color: #3f51b5;
                color: white;
                font-weight: 600;
            }}
            tr:nth-child(even) {{ 
                background-color: #f5f5f5; 
            }}
            tr:hover {{ 
                background-color: #e8eaf6; 
            }}
            a {{ 
                color: #3f51b5; 
                text-decoration: none; 
            }}
            a:hover {{ 
                text-decoration: underline;
                color: #1a237e;
            }}
            blockquote {{
                border-left: 4px solid #3f51b5;
                padding-left: 15px;
                margin-left: 0;
                color: #666;
                font-style: italic;
            }}
            hr {{
                border: none;
                border-top: 2px solid #c5cae9;
                margin: 30px 0;
            }}
        </style>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """
    
    # Save HTML
    print(f"💾 Saving HTML: {output_html}")
    with open(output_html, 'w') as f:
        f.write(styled_html)
    
    print("📑 Generating PDF...")
    try:
        # Use weasyprint (pure Python, no external dependencies)
        HTML(string=styled_html).write_pdf(str(output_pdf))
        print(f"✅ PDF generated successfully: {output_pdf}")
        import os
        file_size = os.path.getsize(output_pdf) / 1024
        print(f"   File size: {file_size:.1f} KB")
        return True
    except Exception as e:
        print(f"❌ PDF generation failed: {e}")
        print(f"   HTML is available: {output_html}")
        return False

if __name__ == "__main__":
    generate_pdf()
