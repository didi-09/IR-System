#!/bin/bash
# Install wkhtmltopdf and generate PDF

echo "Installing wkhtmltopdf..."
sudo apt-get update -qq
sudo apt-get install -y wkhtmltopdf

echo ""
echo "Generating PDF..."
python3 generate_pdf.py

if [ -f "Sentinel_Project_Documentation.pdf" ]; then
    echo "✅ PDF generated successfully!"
    ls -lh Sentinel_Project_Documentation.pdf
else
    echo "❌ PDF generation failed, but HTML is available:"
    ls -lh Sentinel_Project_Documentation.html
fi
