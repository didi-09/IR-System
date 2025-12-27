#!/usr/bin/env python3
"""
Generate a clean, professional PDF from README.md with embedded images
"""

import re
import markdown
from weasyprint import HTML, CSS
from datetime import datetime
import os
from pathlib import Path

def clean_markdown_content(md_content):
    """Remove unwanted sections from markdown content"""
    lines = md_content.split('\n')
    cleaned_lines = []
    
    for i, line in enumerate(lines):
        # Skip the badge lines (lines 7-9)
        if i >= 6 and i <= 8:
            continue
            
        # Skip empty lines after badges
        if i == 9 and line.strip() == '':
            continue
            
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def convert_image_paths(md_content, base_dir):
    """Convert relative image paths to absolute file:// URLs"""
    def replace_image(match):
        alt_text = match.group(1)
        rel_path = match.group(2)
        
        # Convert relative path to absolute
        abs_path = os.path.abspath(os.path.join(base_dir, rel_path))
        file_url = f"file://{abs_path}"
        
        return f'![{alt_text}]({file_url})'
    
    # Replace markdown image syntax: ![alt](path)
    pattern = r'!\[([^\]]*)\]\(([^)]+)\)'
    return re.sub(pattern, replace_image, md_content)

def convert_markdown_to_html(md_content):
    """Convert markdown to HTML with proper styling"""
    
    # Configure markdown extensions for better rendering
    extensions = [
        'markdown.extensions.tables',
        'markdown.extensions.fenced_code',
        'markdown.extensions.codehilite',
        'markdown.extensions.toc',
        'markdown.extensions.nl2br',
        'markdown.extensions.sane_lists'
    ]
    
    # Convert markdown to HTML
    html_content = markdown.markdown(md_content, extensions=extensions)
    
    # Wrap in a complete HTML document with styling
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Sentinel Security Incident Detection & Response System</title>
        <style>
            @page {{
                size: A4;
                margin: 2cm 1.5cm;
                @top-center {{
                    content: "Sentinel IR System Documentation";
                    font-size: 10pt;
                    color: #666;
                }}
                @bottom-center {{
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 9pt;
                    color: #666;
                }}
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 100%;
                margin: 0;
                padding: 0;
            }}
            
            h1 {{
                color: #2c3e50;
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
                margin-top: 30px;
                margin-bottom: 20px;
                font-size: 28pt;
                page-break-after: avoid;
            }}
            
            h2 {{
                color: #34495e;
                border-bottom: 2px solid #95a5a6;
                padding-bottom: 8px;
                margin-top: 25px;
                margin-bottom: 15px;
                font-size: 20pt;
                page-break-after: avoid;
            }}
            
            h3 {{
                color: #2c3e50;
                margin-top: 20px;
                margin-bottom: 12px;
                font-size: 16pt;
                page-break-after: avoid;
            }}
            
            h4 {{
                color: #34495e;
                margin-top: 15px;
                margin-bottom: 10px;
                font-size: 13pt;
                page-break-after: avoid;
            }}
            
            p {{
                margin-bottom: 12px;
                text-align: justify;
            }}
            
            ul, ol {{
                margin-bottom: 15px;
                padding-left: 30px;
            }}
            
            li {{
                margin-bottom: 6px;
            }}
            
            table {{
                border-collapse: collapse;
                width: 100%;
                margin: 15px 0;
                font-size: 10pt;
                page-break-inside: avoid;
            }}
            
            th {{
                background-color: #3498db;
                color: white;
                padding: 10px;
                text-align: left;
                font-weight: bold;
            }}
            
            td {{
                border: 1px solid #ddd;
                padding: 8px;
            }}
            
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            
            code {{
                background-color: #f4f4f4;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 9pt;
                color: #c7254e;
            }}
            
            pre {{
                background-color: #2c3e50;
                color: #ecf0f1;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                margin: 15px 0;
                page-break-inside: avoid;
            }}
            
            pre code {{
                background-color: transparent;
                color: #ecf0f1;
                padding: 0;
            }}
            
            blockquote {{
                border-left: 4px solid #3498db;
                padding-left: 15px;
                margin-left: 0;
                color: #555;
                font-style: italic;
                background-color: #f8f9fa;
                padding: 10px 15px;
                margin: 15px 0;
            }}
            
            hr {{
                border: none;
                border-top: 2px solid #e0e0e0;
                margin: 25px 0;
            }}
            
            .emoji {{
                font-size: 1.2em;
            }}
            
            strong {{
                color: #2c3e50;
                font-weight: 600;
            }}
            
            a {{
                color: #3498db;
                text-decoration: none;
            }}
            
            a:hover {{
                text-decoration: underline;
            }}
            
            /* Image styling */
            img {{
                max-width: 100%;
                height: auto;
                display: block;
                margin: 20px auto;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                page-break-inside: avoid;
            }}
            
            /* First page title styling */
            body > h1:first-of-type {{
                font-size: 32pt;
                text-align: center;
                color: #2c3e50;
                margin-top: 50px;
                margin-bottom: 10px;
                border-bottom: none;
            }}
            
            /* Subtitle styling */
            body > p:first-of-type {{
                text-align: center;
                font-size: 14pt;
                color: #7f8c8d;
                margin-bottom: 20px;
                font-weight: 500;
            }}
            
            /* Second paragraph (description) */
            body > p:nth-of-type(2) {{
                text-align: center;
                font-size: 11pt;
                color: #555;
                margin-bottom: 40px;
                padding: 0 50px;
            }}
        </style>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """
    
    return full_html

def main():
    """Main function to generate PDF"""
    
    # File paths
    base_dir = '/home/kali/IR-Project/IR-System'
    readme_path = os.path.join(base_dir, 'README.md')
    output_path = os.path.join(base_dir, 'Sentinel_Project_Documentation.pdf')
    
    print("🛡️  Sentinel PDF Generator")
    print("=" * 50)
    
    # Read README.md
    print("📖 Reading README.md...")
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            md_content = f.read()
    except FileNotFoundError:
        print(f"❌ Error: README.md not found at {readme_path}")
        return 1
    
    # Clean the markdown content (remove badges)
    print("🧹 Cleaning content (removing badges)...")
    cleaned_md = clean_markdown_content(md_content)
    
    # Convert image paths to absolute URLs
    print("🖼️  Converting image paths...")
    cleaned_md = convert_image_paths(cleaned_md, base_dir)
    
    # Convert to HTML
    print("🔄 Converting Markdown to HTML...")
    html_content = convert_markdown_to_html(cleaned_md)
    
    # Generate PDF
    print("📄 Generating PDF with images...")
    try:
        HTML(string=html_content).write_pdf(output_path)
        print(f"✅ PDF generated successfully!")
        print(f"📁 Location: {output_path}")
        
        # Get file size
        file_size = os.path.getsize(output_path)
        print(f"📊 File size: {file_size / 1024:.2f} KB")
        
    except Exception as e:
        print(f"❌ Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    print("=" * 50)
    print("✨ Done!")
    return 0

if __name__ == "__main__":
    exit(main())
