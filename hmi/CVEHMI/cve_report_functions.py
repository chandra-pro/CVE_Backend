"""
====================
cvechecker_report_functions.py
Helper Functions for Report Generation of CVEHMI Tool
author: Shubham
===================
"""



import os
import pandas as pd
import base64
import numpy as np
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, PageBreak, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet

######################################################################################################
# Generate HTML Report

def generate_html_report(data, output_html_path, include_sections, filters, manifest_file, report_date):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CVE Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            h1, h2 {{
                color: #2c3e50;
            }}
            h1 {{
                border-bottom: 2px solid #3498db;
                padding-bottom: 10px;
            }}
            .package-list {{
                background-color: #fff;
                border-radius: 5px;
                padding: 15px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }}
            .package-list a {{
                color: #3498db;
                text-decoration: none;
            }}
            .package-list a:hover {{
                text-decoration: underline;
            }}
            .vendor {{
                margin-top: 20px;
                font-weight: bold;
                color: #2c3e50;
                background-color: #ecf0f1;
                padding: 10px;
                border-radius: 5px;
            }}
            .cve-id {{
                cursor: pointer;
                color: #3498db;
                margin: 10px 0;
            }}
            .cve-id:hover {{
                text-decoration: underline;
            }}
            .details {{
                display: none;
                margin-left: 20px;
                border-left: 3px solid #3498db;
                padding: 10px;
                background-color: #fff;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            .heading-red {{
                color: red;
                font-weight: bold;
                margin-top: 10px;
            }}
            .separator {{
                border-top: 3px solid #34495e;
                margin: 30px 0;
            }}
            .back-to-top {{
                position: fixed;
                bottom: 20px;
                right: 20px;
                background-color: #3498db;
                color: white;
                padding: 10px 15px;
                border-radius: 5px;
                text-decoration: none;
            }}
        </style>
        <script>
            function toggleDetails(uniqueId) {{
                var details = document.getElementById(uniqueId);
                if (details.style.display === "none" || details.style.display === "") {{
                    details.style.display = "block";
                }} else {{
                    details.style.display = "none";
                }}
            }}
        </script>
    </head>
    <body>
        <h1>CVE Report</h1>
        <p><strong>Processed Manifest File:</strong> {manifest_file}</p>
        <p><strong>Date of Report Generation:</strong> {report_date}</p>
        <div class="package-list">
            <h2>Packages</h2>
            <ul>
    """

    # Create a list of packages with CVEs
    packages_with_cves = [f"{df['Package Name'].iloc[0]} (Version: {df['Version'].iloc[0]})" 
                          for df in data.values() if not df.empty]

    # Add links to packages in the table of contents
    for package in packages_with_cves:
        package_name = package.split(' (')[0]
        package_version = package.split(' (Version: ')[1].strip(')')
        package_id = f"{package_name.replace(' ', '_').replace(':', '_').replace('(', '').replace(')', '').replace('.', '_')}_{package_version.replace(' ', '_')}"
        html_content += f'<li><a href="#{package_id}">{ package}</a></li>'

    html_content += """
            </ul>
        </div>
    """

    for package_version, df in data.items():
        if df.empty:
            continue  # Skip this package if no CVEs match the filters

        package = df['Package Name'].iloc[0]
        version = df['Version'].iloc[0]  # This might be a float
        package_id = f"{package.replace(' ', '_').replace(':', '_').replace('(', '').replace(')', '').replace('.', '_')}_{str(version).replace(' ', '_')}"

        html_content += f"""
        <div class="separator"></div>
        <h2 id="{package_id}">{package} (Version: {version})</h2>
        """

        vendors = df['Vendor Name'].unique()
        for vendor in vendors:
            vendor_df = df[df['Vendor Name'] == vendor]
            html_content += f'<div class="vendor">Vendor: {vendor}</div>'
            
            # Add an ordered list for CVE IDs
            html_content += '<ol>'
            
            for index, (_, row) in enumerate(vendor_df.iterrows(), start=1):
                unique_id = f"{row['CVE ID']}_{package_id}".replace('-', '_').replace('.', '_')
                html_content += f"""
                <li>
                    <div class="cve-id" onclick="toggleDetails('{unique_id}_details')">{row['CVE ID']}</div>
                    <div id="{unique_id}_details" class="details">
                        <p><strong>Vulnerability Status:</strong> {row['Vulnerability Status'] if pd.notna(row['Vulnerability Status']) else 'Not Available'}</p>
                        <p><strong>Published Date:</strong> {row['Published Date'] if pd.notna(row['Published Date']) else 'Not Available'}</p>
                        <p><strong>Last Modified:</strong> {row['Last Modified'] if pd.notna(row['Last Modified']) else 'Not Available'}</p>
                """

                if 'Description' in include_sections:
                    html_content += f"""
                        <p class="heading-red">Description:</p>
                        <p><strong></strong> {row['Description'] if pd.notna(row['Description']) else 'Not Available'}</p>
                    """

                if 'CVSSV2' in include_sections:
                    html_content += f"""
                        <p class="heading-red">CVSS V2 Details:</p>
                        <p><strong>Source:</strong> {row['CVSS V2 Source'] if pd.notna(row['CVSS V2 Source']) else 'Not Available'}</p>
                        <p><strong>Version:</strong> {row['CVSS V2 Version'] if pd.notna(row['CVSS V2 Version']) else 'Not Available'}</p>
                        <p><strong>Vector String:</strong> {row['CVSS V2 Vector String'] if pd.notna(row['CVSS V2 Vector String']) else 'Not Available'}</p>
                        <p><strong>Access Vector:</strong> {row['CVSS V2 Access Vector'] if pd.notna(row['CVSS V2 Access Vector']) else 'Not Available'}</p>
                        <p><strong>Base Score:</strong> {str(row['CVSS V2 Base Score']) if pd.notna(row['CVSS V2 Base Score']) else 'Not Available'}</p>
                        <p><strong>Exploitability Score:</strong> {str(row['CVSS V2 Exploitability Score']) if pd.notna(row['CVSS V2 Exploitability Score']) else 'Not Available'}</p>
                        <p><strong>Impact Score:</strong> {str(row['CVSS V2 Impact Score']) if pd.notna(row['CVSS V2 Impact Score']) else 'Not Available'}</p>
                    """

                if 'CVSSV3.1' in include_sections:
                    html_content += f"""
                        <p class="heading-red">CVSS V3.1 Details:</p>
                        <p><strong>Source:</strong> {row['CVSS V3.1 Source'] if pd.notna(row['CVSS V3.1 Source']) else 'Not Available'}</p>
                        <p><strong>Version:</strong> {row['CVSS V3.1 Version'] if pd.notna(row['CVSS V3.1 Version']) else 'Not Available'}</p>
                        <p><strong>Vector String:</strong> {row['CVSS V3.1 Vector String'] if pd.notna(row['CVSS V3.1 Vector String']) else 'Not Available'}</p>
                        <p><strong>Attack Vector :</strong> {row['CVSS V3.1 Attack Vector'] if pd.notna(row['CVSS V3.1 Attack Vector']) else 'Not Available'}</p>
                        <p><strong>Privileges Required:</strong> {row['CVSS V3.1 Privileges Required'] if pd.notna(row['CVSS V3.1 Privileges Required']) else 'Not Available'}</p>
                        <p><strong>Base Score:</strong> {str(row['CVSS V3.1 Base Score']) if pd.notna(row['CVSS V3.1 Base Score']) else 'Not Available'}</p>
                        <p><strong>Exploitability Score:</strong> {str(row['CVSS V3.1 Exploitability Score']) if pd.notna(row['CVSS V3.1 Exploitability Score']) else 'Not Available'}</p>
                        <p><strong>Impact Score:</strong> {str(row['CVSS V3.1 Impact Score']) if pd.notna(row['CVSS V3.1 Impact Score']) else 'Not Available'}</p>
                    """

                if 'Weaknesses' in include_sections:
                    html_content += f"""
                        <p class="heading-red">Weaknesses:</p>
                        <p>{row['Weakness Details'] if pd.notna(row['Weakness Details']) else 'Not Available'}</p>
                    """

                if 'References' in include_sections:
                    html_content += f"""
                        <p class="heading-red">References:</p>
                    """
                    references = row['Reference Details'].split(' | ')
                    for ref in references:
                        html_content += f'<div class="reference">{ref if ref else "Not Available"}</div>'

                html_content += '</div></li>'
            
            html_content += '</ol>'

    html_content += """
        <a href="#" class="back-to-top">Back to Top</a>
    </body>
    </html>
    """

    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def file_to_base64(file_path):
    
    with open(file_path, "rb") as file:
        return base64.b64encode(file.read()).decode('utf-8')
    
#######################################################################################################
# Generate PDF Report

def generate_pdf(excel_file_path, output_pdf_path, manifest_file, report_date, page_margin=0.5):
    # Define mandatory and optional columns
    mandatory_columns = ["CVE ID", "Published Date"]
    optional_cvss_columns = {
        'v2': ["CVSS V2 Base Score", "CVSS V2 Access Vector"],
        'v3': ["CVSS V3.1 Base Score", "CVSS V3.1 Attack Vector"]
    }
    
    # Load the Excel file
    excel_data = pd.ExcelFile(excel_file_path)
    sheet_names = excel_data.sheet_names
    
    # Set up the PDF document
    page_margin = inch * page_margin
    pdf = SimpleDocTemplate(
        output_pdf_path,
        pagesize=landscape(A4),
        leftMargin=page_margin,
        rightMargin=page_margin,
        topMargin=page_margin,
        bottomMargin=page_margin
    )
    
    styles = getSampleStyleSheet()
    elements = []
    
    # Add manifest file name and report generation date
    elements.append(Paragraph(f"Processed Manifest File: {manifest_file}", styles["Normal"]))
    elements.append(Paragraph(f"Date of Report Generation: {report_date}", styles["Normal"]))
    elements.append(Spacer(1, 0.5 * inch))
    
    # Page layout constants
    page_width = landscape(A4)[0]
    table_width = page_width - 2 * page_margin
    
    # Table of Contents styling
    toc_title_style = styles["Title"]
    toc_title_style.fontSize = 20
    toc_title_style.leading = 24
    toc_title_style.fontName = "Helvetica-Bold"
    elements.append(Paragraph("Table of Contents", toc_title_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    # TOC sheet names styling
    toc_sheet_style = styles["BodyText"]
    toc_sheet_style.fontSize = 11
    toc_sheet_style.leading = 13
    toc_sheet_style.fontName = "Times-Roman"
    
    # Add sheet names to TOC
    for idx, sheet_name in enumerate(sheet_names):
        link = f'<a href="#{sheet_name}">• {idx + 1}. {sheet_name}</a>'
        elements.append(Paragraph(link, toc_sheet_style))
        elements.append(Spacer(1, 0.08 * inch))
    
    elements.append(Spacer(1, 0.3 * inch))
    
    # Process each sheet
    for sheet_name in sheet_names:
        elements.append(PageBreak())
        
        # Sheet header styling
        sheet_header_style = styles["Heading1"]
        sheet_header_style.fontSize = 16
        sheet_header_style.spaceBefore = 0
        sheet_header_style.spaceAfter = 0
        elements.append(Paragraph(f'<a name="{sheet_name}"/>{sheet_name}', sheet_header_style))
        elements.append(Spacer(1, 0.2 * inch))
        
        df = pd.read_excel(excel_data, sheet_name=sheet_name)
        
        # Check if this is the "No CVEs" case
        if sheet_name == "No CVEs":
            # Create a message style
            message_style = styles["Normal"]
            message_style.fontSize = 12
            message_style.leading = 14
            message_style.alignment = 1  # Center alignment
            
            # Add the "No CVE data found" message
            elements.append(Paragraph("No CVE data found", message_style))
            continue
        
        # Regular case processing continues here
        # Check for mandatory columns
        if not all(column in df.columns for column in mandatory_columns):
            raise ValueError(f"Sheet '{sheet_name}' is missing one or more mandatory columns: {mandatory_columns}")
        
        # Initialize selected columns with mandatory columns
        selected_columns = mandatory_columns.copy()
        
        # Check for CVSS v2 columns
        if all(col in df.columns for col in optional_cvss_columns['v2']):
            selected_columns.extend(optional_cvss_columns['v2'])
            
        # Check for CVSS v3 columns
        if all(col in df.columns for col in optional_cvss_columns['v3']):
            selected_columns.extend(optional_cvss_columns['v3'])
        
        data = df[selected_columns]
        data.insert(0, "S.I.", range(1 , len(data) + 1))
        
        # Table styles
        table_style = styles["BodyText"]
        table_style.fontSize = 8
        table_style.leading = 10
        
        header_style = styles["BodyText"]
        header_style.fontSize = 8
        header_style.leading = 10
        
        # Create table data
        header_cells = [Paragraph(col, header_style) for col in ["S.I."] + selected_columns]
        table_data = [header_cells]
        
        for row in data.values:
            wrapped_row = [Paragraph(str(cell) if not pd.isna(cell) else "", table_style) for cell in row]
            table_data.append(wrapped_row)
        
        # Calculate dynamic column widths based on content and present columns
        total_columns = len(selected_columns) + 1  # +1 for S.I. column
        
        # Initialize base column widths
        width_allocation = {
            "S.I.": 0.05,
            "CVE ID": 0.20,
            "Published Date": 0.15
        }
        
        # Calculate actual widths based on present columns
        column_widths = [table_width * width_allocation["S.I."]]  # S.I. column
        
        remaining_width = table_width * (1 - width_allocation["S.I."])
        present_columns = selected_columns.copy()
        
        # Calculate width for present columns
        base_width = width_allocation["CVE ID"] + width_allocation["Published Date"]
        cvss_columns = [col for col in present_columns if col not in width_allocation]
        
        # Adjust widths based on present columns
        if cvss_columns:
            remaining_cvss_width = (1 - base_width - width_allocation["S.I."]) / len(cvss_columns)
            for col in present_columns:
                if col in width_allocation:
                    column_widths.append(table_width * width_allocation[col])
                else:
                    column_widths.append(table_width * remaining_cvss_width)
        else:
            # If no CVSS columns, distribute width between CVE ID and Published Date
            scale_factor = (1 - width_allocation["S.I."]) / base_width
            for col in present_columns:
                column_widths.append(table_width * (width_allocation[col] * scale_factor))
        
        # Create and style table
        table = Table(table_data, colWidths=column_widths, repeatRows=1)
        table.setStyle(TableStyle([
            # Header styling
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            
            # Content styling
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),  # S.I. column
            ("ALIGN", (1, 1), (1, -1), "LEFT"),    # CVE ID
            
            # Grid styling
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("LINEBELOW", (0, 0), (-1, 0), 1, colors.black),
            
            # Cell padding
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ]))
        
        elements.append(table)
    
    # Build the PDF
    pdf.build(elements)
    return output_pdf_path

def generate_download_html(scan_id, username, project_id, excel_report, html_report, output_dir, output_report_dir, manifest_file, report_date, report_name):
    """Generates an HTML file with embedded download links for the reports and shows the complete HTML report."""
   

    pdf_report = os.path.join(output_report_dir, f'{report_name}.pdf')
    
    generate_pdf(excel_report, pdf_report, manifest_file, report_date)
    
    excel_base64 = file_to_base64(excel_report)
    html_base64 = file_to_base64(html_report)
    pdf_base64 = file_to_base64(pdf_report)

    download_html_path = os.path.join(output_dir, f'download_{scan_id}.html')

    with open(download_html_path, 'w') as f:
        f.write(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Download Reports</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                }}
                h1, h2 {{
                    color: #0056b3;
                    border-bottom: 2px solid #0056b3;
                    padding-bottom: 10px;
                }}
                .container {{
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .download-link {{
                    display: inline-block;
                    margin: 10px 10px 10px 0;
                    padding: 10px 15px;
                    background-color: #0056b3;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    transition: background-color 0.3s ease;
                }}
                .download-link:hover {{
                    background-color: #003d82;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Download Reports</h1>
                <a href="data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{excel_base64}" download="{report_name}.xlsx" class="download-link">Download Excel Report</a>
                <a href="data:text/html;base64,{html_base64}" download="{report_name}.html" class="download-link">Download HTML Report</a>
                <a href="data:application/pdf;base64,{pdf_base64}" download="{report_name}.pdf" class="download-link">Download PDF Report</a>
            </div>
            
            <div class="container">
                <h2>HTML Report</h2>
                <div>
                    {open(html_report).read()}
                </div>
            </div>
        </body>
        </html>
        """)
    
#############################################################################################################
# Generate Empty Excel and HTML Reports when no CVE IDs are found

def write_empty_excel(file_path):
    df_empty = pd.DataFrame({'Message': ['No CVE data found']})
    with pd.ExcelWriter(file_path) as writer:
        df_empty.to_excel(writer, sheet_name='No CVEs', index=False)

def generate_empty_html_report(file_path, sections):
    with open(file_path, 'w') as html_file:
        html_file.write("<html><head><title>No CVEs Found</title></head>")
        html_file.write("<body><h1>No CVE data available</h1></body></html>")

###############################################################################################################