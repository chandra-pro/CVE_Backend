"""
====================
pkct_report_functions.py
Helper Functions for Report Generation of PKCT Tool
Author: Shubham
====================
 
"""

import os
import pandas as pd
import base64
from openpyxl import load_workbook
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, PageBreak, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


# Generate HTML Report for PKCT Scan

def generate_html_report(excel_file, output_html_path, patch_files_dir, result_file_path, package_name, version, sections=None, manifest_file=None, report_date=None):
    # Load the Excel file
    wb = load_workbook(excel_file)
    ws = wb.active

    # Read the Excel data into a DataFrame
    data = pd.DataFrame(ws.values)
    data.columns = data.iloc[0]  # Set the first row as header
    data = data[1:].reset_index(drop=True)  # Remove the header row from data

    # Replace None and NaN values with "Not Available"
    data = data.fillna("Not Available")
    
    # Start HTML structure with the same styling as before
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Patch Report</title>
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
            h1 {{
                color: #2c3e50;
                text-align: center;
                margin-bottom: 30px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                background-color: #fff;
                box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }}
            th {{
                background-color: #3498db;
                color: white;
                font-weight: bold;
            }}
            tr:nth-child(even) {{
                background-color: #f2f2f2;
            }}
            .cve-details {{
                background-color: #fff;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
                margin-top: 10px;
            }}
            .cve-details h3 {{
                color: #2c3e50;
                margin-top: 0;
            }}
            .clickable {{
                color: #3498db;
                cursor: pointer;
                text-decoration: underline;
            }}
        </style>
        <script>
            function toggleDetails(cveId) {{
                var details = document.getElementById('details-' + cveId);
                if (details.style.display === 'none') {{
                    details.style.display = 'block';
                }} else {{
                    details.style.display = 'none';
                }}
            }}
        </script>
    </head>
    <body>
        <h1>Patch Report</h1>
        <div class="report-info">
    """

    # Condition to display manifest file or package name/version
    if manifest_file:
        html_content += f"<p><strong>Processed Manifest Filename:</strong> {manifest_file}</p>"
    else:
        html_content += f"<p><strong>Package Name:</strong> Kernel</p>"
        if version:
            html_content += f"<p><strong>Version:</strong> {version}</p>  "
    
    # Add the report date (if available)
    html_content += f"<p><strong>Date of Report Generation:</strong> {report_date if report_date else 'Not Available'}</p>"

    html_content += "</div><table><tr><th>#</th><th>CVE ID</th><th>Patch Status</th><th>Status Detail</th></tr>"

    # Helper function to safely get values
    def get_safe_value(row, key, default="Not Available"):
        value = row.get(key)
        if value is None or pd.isna(value) or value == "None" or value == "":
            return default
        return str(value)

    # Populate the table with indexed CVE IDs and their status
    for index, row in data.iterrows():
        cve_id = get_safe_value(row, 'CVE Id')
        status_detail = get_safe_value(row, 'Status Detail')
        patch_status = get_safe_value(row, 'Patch Status')
        
        html_content += f"""
        <tr>
            <td>{index + 1}</td>
            <td onclick="toggleDetails('{cve_id}')" class="clickable">{cve_id}</td>
            <td>{patch_status}</td>
            <td class="status-detail">{status_detail}</td>
        </tr>
        <tr>
            <td colspan="4">
                <div id="details-{cve_id}" class="cve-details" style="display: none;">
                    <h3>CVE Details</h3>
                    <div><strong>Patch File URL:</strong> <a href="{get_safe_value(row, 'Patch File URL')}" target="_blank">{get_safe_value(row, 'Patch File URL')}</a></div>
                    <div><strong>Source Identifier:</strong> {get_safe_value(row, 'Source Identifier')}</div>
                    <div><strong>Published:</strong> {get_safe_value(row, 'Published')}</div>
                    <div><strong>Last Modified:</strong> {get_safe_value(row, 'Last Modified')}</div>
                    <div><strong>Vulnerability Status:</strong> {get_safe_value(row, 'Vulnerability Status')}</div>
        """

        if sections is None:
            sections = [
                "Description", "CVSSV2", "CVSSV3.1", "Weaknesses", "References"
            ]

        # Add additional data based on the sections argument
        if "Description" in sections:
            html_content += f"<div><strong>Description:</strong> {get_safe_value(row, 'Description')}</div>"
        if "CVSSV2" in sections:
            html_content += f"""
            <div><strong>CVSS V2:</strong></div>
            <div>Source: {get_safe_value(row, 'CVSS v2 Source')}</div>
            <div>Version: {get_safe_value(row, 'CVSS v2 Version')}</div>
            <div>Vector String: {get_safe_value(row, 'CVSS v2 Vector String')}</div>
            <div>Access Vector: {get_safe_value(row, 'CVSS v2 Access Vector')}</div>
            <div>Base Score: {get_safe_value(row, 'CVSS v2 Base Score')}</div>
            <div>Exploitability Score: {get_safe_value(row, 'CVSS v2 Exploitability Score')}</div>
            <div>Impact Score: {get_safe_value(row, 'CVSS v2 Impact Score')}</div>
            """
        if "CVSSV3.1" in sections:
            html_content += f"""
            <div><strong>CVSS V3.1:</strong></div>
            <div>Source: {get_safe_value(row, 'CVSS v3.1 Source')}</div>
            <div>Version: {get_safe_value(row, 'CVSS v3.1 Version')}</div>
            <div>Vector String: {get_safe_value(row, 'CVSS v3.1 Vector String')}</div>
            <div>Attack Vector: {get_safe_value(row, 'CVSS v3.1 Attack Vector')}</div>
            <div>Privileges Required: {get_safe_value(row, 'CVSS v3.1 Privileges Required')}</div>
            <div>Base Score: {get_safe_value(row, 'CVSS v3.1 Base Score')}</div>
            <div>Exploitability Score: {get_safe_value(row, 'CVSS v3.1 Exploitability Score')}</div>
            <div>Impact Score: {get_safe_value(row, 'CVSS v3.1 Impact Score')}</div>
            """
        if "Weaknesses" in sections:
            html_content += f"<div><strong>Weaknesses:</strong> {get_safe_value(row, 'Weaknesses')}</div>"
        if "References" in sections:
            references = get_safe_value(row, 'References', '').split(', URL:') if isinstance(get_safe_value(row, 'References'), str) else []
            references_html = "<ol>" + "".join([f"<li>{ref.strip()}</li>" for ref in references if ref.strip()]) + "</ol>" if references else "Not Available"
            html_content += f"<div><strong>References:</strong> {references_html}</div>"

        html_content += """
                </div>
            </td>
        </tr>
        """

    # End the HTML structure
    html_content += """
        </table>
    </body>
    </html>
    """

    # Write the HTML content to the output file
    with open(output_html_path, 'w', encoding='utf-8') as file:
        file.write(html_content)

    print(f"HTML report generated: {output_html_path}")
    

def file_to_base64(file_path):
    """Converts a file to a base64-encoded string."""
    with open(file_path, "rb") as file:
        return base64.b64encode(file.read()).decode('utf-8')

######################################################################################################
# Generate PDF Report

def generate_pdf(excel_file_path, output_pdf_path, version, manifest_file, report_date, page_margin=0.5):
    # Define mandatory and optional columns
    mandatory_columns = ["CVE Id", "Published", "Patch Status", "Status Detail"]
    optional_cvss_columns = {
        'v2': ["CVSS v2 Base Score", "CVSS v2 Access Vector"],
        'v3': ["CVSS v3.1 Base Score", "CVSS v3.1 Attack Vector"]
    }
    
    # Load the Excel file
    df = pd.read_excel(excel_file_path)
    
    # Check for mandatory columns
    if not all(column in df.columns for column in mandatory_columns):
        raise ValueError(f"Excel file is missing one or more mandatory columns: {mandatory_columns}")
    
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
    if manifest_file:
        elements.append(Paragraph(f"Processed Manifest File: {manifest_file}", styles["Normal"]))
    else:
        elements.append(Paragraph("Package Name: Kernel", styles["Normal"]))
        elements.append(Paragraph(f"Version: {version}", styles["Normal"]))

    elements.append(Paragraph(f"Date of Report Generation: {report_date}", styles["Normal"]))
    elements.append(Spacer(1, 0.5 * inch))
    
    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    elements.append(Paragraph("PATCH REPORT", title_style))
    
    # Page layout constants
    page_width = landscape(A4)[0]
    table_width = page_width - 2 * page_margin
    
    # Initialize selected columns with mandatory columns
    selected_columns = mandatory_columns.copy()
    
    # Check for CVSS v2 columns
    if all(col in df.columns for col in optional_cvss_columns['v2']):
        selected_columns.extend(optional_cvss_columns['v2'])
        
    # Check for CVSS v3 columns
    if all(col in df.columns for col in optional_cvss_columns['v3']):
        selected_columns.extend(optional_cvss_columns['v3'])
    
    data = df[selected_columns]
    data.insert(0, "S.I.", range(1, len(data) + 1))
    
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
    
    # Initialize column widths dictionary
    width_allocation = {
        "S.I.": 0.05,
        "CVE ID": 0.15,
        "Published Date": 0.10,
        "Patch Status": 0.15,
        "Status Detail": 0.20
    }
    
    # Calculate actual widths
    column_widths = [table_width * width_allocation["S.I."]]  # S.I. column
    remaining_width = table_width * (1 - width_allocation["S.I."])
    present_columns = selected_columns.copy()
    
    # Calculate width for present columns
    base_columns_width = sum(width_allocation[col] for col in present_columns if col in width_allocation)
    cvss_columns = [col for col in present_columns if col not in width_allocation]
    
    # Adjust widths based on present columns
    if cvss_columns:
        cvss_width = (1 - base_columns_width) / len(cvss_columns)
        for col in present_columns:
            if col in width_allocation:
                column_widths.append(table_width * width_allocation[col])
            else:
                column_widths.append(table_width * cvss_width)
    else:
        # If no CVSS columns, distribute remaining width proportionally
        scale_factor = 1 / base_columns_width
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

def generate_download_html(scan_id, username, project_id, excel_report, html_report, output_report_dir, output_dir, version, manifest_file=None, report_date=None, report_name=None):
    
    
    pdf_report = os.path.join(output_report_dir, f'{report_name}.pdf')
    generate_pdf(excel_report, pdf_report, version, manifest_file, report_date)
    
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