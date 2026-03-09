pipeline {
    agent any

    environment {
        JUICE_SHOP_REPO = 'https://github.com/mile9299/juice-shopv21.git'
        DOCKER_PORT = 3000
        SPECTRAL_DSN = credentials('SPECTRAL_DSN')
        CS_IMAGE_NAME = 'mile/cs-fcs'
        CS_IMAGE_TAG = '2.2.0'
        CS_CLIENT_ID = credentials('CS_CLIENT_ID')
        CS_CLIENT_SECRET = credentials('CS_CLIENT_SECRET')
        CS_USERNAME = 'mile'
        CS_PASSWORD = credentials('CS_PASSWORD')
        CS_REGISTRY = 'registry.crowdstrike.com'
        FALCON_CLIENT_ID = credentials('CS_CLIENT_ID')
        FALCON_CLIENT_SECRET = credentials('CS_CLIENT_SECRET')
        FALCON_REGION = 'us-1'
        PROJECT_PATH = 'git::https://github.com/hashicorp/terraform-guides.git'
        CONTAINER_REPO = 'juice-shop'
        CONTAINER_TAG = 'latest'
    }

    tools {
        nodejs 'NodeJS 18.0.0'
    }

    stages {
        stage('Checkout') {
            steps {
                script {
                    checkout([$class: 'GitSCM', branches: [[name: '*/main']], doGenerateSubmoduleConfigurations: false, extensions: [], submoduleCfg: [], userRemoteConfigs: [[url: JUICE_SHOP_REPO]]])
                }
            }
        }

        stage('Falcon Cloud Security IaC Scan') {
            steps {
                script {
                    def SCAN_EXIT_CODE = sh(
                        script: '''
                            set +x
                            scan_status=0
                            if [ -z "$CS_USERNAME" ] || [ -z "$CS_PASSWORD" ] || [ -z "$CS_REGISTRY" ] || [ -z "$CS_IMAGE_NAME" ] || [ -z "$CS_IMAGE_TAG" ] || [ -z "$CS_CLIENT_ID" ] || [ -z "$CS_CLIENT_SECRET" ] || [ -z "$FALCON_REGION" ] || [ -z "$PROJECT_PATH" ]; then
                                echo "Error: required environment variables/params are not set"
                                exit 1
                            else
                                echo "Logging in to crowdstrike registry with username: $CS_USERNAME"
                                echo "$CS_PASSWORD" | docker login --username "$CS_USERNAME" --password-stdin

                                if [ $? -eq 0 ]; then
                                    echo "Docker login successful"
                                    echo "Pulling fcs container target from crowdstrike"
                                    docker pull "$CS_IMAGE_NAME:$CS_IMAGE_TAG"
                                    if [ $? -eq 0 ]; then
                                        echo "fcs docker container image pulled successfully"
                                        echo "=============== FCS IaC Scan Starts ==============="

                                        mkdir -p "$WORKSPACE/iac_reports"
                                        chmod 777 "$WORKSPACE/iac_reports"
                                        docker run --network=host --rm \
                                            -v "$WORKSPACE/iac_reports:/reports" \
                                            "$CS_IMAGE_NAME:$CS_IMAGE_TAG" \
                                            --client-id "$CS_CLIENT_ID" \
                                            --client-secret "$CS_CLIENT_SECRET" \
                                            --falcon-region "$FALCON_REGION" \
                                            scan iac -p "$PROJECT_PATH" \
                                            --report-formats json \
                                            --output-path /reports || true

                                        scan_status=$?
                                        echo "=============== FCS IaC Scan Ends ==============="

                                        # Find the newest scan output file (FCS creates timestamped files)
                                        echo "Looking for IaC scan results..."
                                        ls -lah "$WORKSPACE/iac_reports/" || echo "No iac_reports directory"

                                        # Find the newest *-scan-results.json file
                                        SCAN_FILE=$(find "$WORKSPACE/iac_reports" -name "*-scan-results.json" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2)

                                        if [ -n "$SCAN_FILE" ] && [ -f "$SCAN_FILE" ]; then
                                            echo "✅ Found latest scan file: $SCAN_FILE"
                                            cp "$SCAN_FILE" "$WORKSPACE/iac_scan_results.json"
                                        elif [ -f "$WORKSPACE/iac_reports/iac_scan_results.json" ]; then
                                            echo "Found: iac_scan_results.json"
                                            cp "$WORKSPACE/iac_reports/iac_scan_results.json" "$WORKSPACE/iac_scan_results.json"
                                        else
                                            echo "❌ No scan results found, creating empty file"
                                            echo '{"resources": []}' > "$WORKSPACE/iac_scan_results.json"
                                        fi

                                        echo "IaC scan results file size:"
                                        ls -lh "$WORKSPACE/iac_scan_results.json"
                                    else
                                        echo "Error: failed to pull fcs docker image from crowdstrike"
                                        scan_status=1
                                    fi
                                else
                                    echo "Error: docker login failed"
                                    scan_status=1
                                fi
                            fi
                            exit $scan_status
                        ''', returnStatus: true
                    )
                    echo "fcs-iac-scan-status: ${SCAN_EXIT_CODE}"
                    if (SCAN_EXIT_CODE == 40) {
                        currentBuild.result = 'UNSTABLE'
                    } else if (SCAN_EXIT_CODE == 0) {
                        currentBuild.result = 'SUCCESS'
                    } else {
                        echo "Scan had issues but continuing..."
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    script {
                        // Write Python script to file, then execute
                        writeFile file: 'generate_iac_report.py', text: '''import json
from datetime import datetime
from collections import Counter, defaultdict
import os

def load_scan_results(json_file):
    """Load IaC scan results from JSON file"""
    try:
        with open(json_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {json_file}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {json_file}: {e}")
        return []

def get_severity_name(severity_code):
    """Convert severity code to name"""
    severity_map = {
        0: 'informational',
        1: 'medium',
        2: 'high',
        3: 'critical'
    }
    return severity_map.get(severity_code, 'low')

def get_falcon_console_url(region='us-1', filter_query=''):
    """Generate Falcon Console URL"""
    base_urls = {
        'us-1': 'https://falcon.crowdstrike.com',
        'us-2': 'https://falcon.us-2.crowdstrike.com',
        'eu-1': 'https://falcon.eu-1.crowdstrike.com'
    }
    base_url = base_urls.get(region, 'https://falcon.crowdstrike.com')

    if filter_query:
        return f"{base_url}/cloud-security/iac/ng-detections?{filter_query}"
    return f"{base_url}/cloud-security/iac/ng-detections?page=1"

def generate_html_report(scan_results, output_file, customer_id="5DDB0407BEF249C19C7A975F17979A1F-90",
                         pipeline_name="IaC Security Scan", build_number="N/A", build_id="N/A", region='us-1'):
    """Generate Dark-themed HTML report with clickable links"""

    if not scan_results:
        print("No scan results to process")
        return False

    # Calculate statistics
    total_violations = len(scan_results)
    projects = set(finding['project_name'] for finding in scan_results)
    total_projects = len(projects)
    files = set(finding['file_name'] for finding in scan_results)
    total_files = len(files)

    # Count severities
    severity_counts = Counter()
    for finding in scan_results:
        severity_name = get_severity_name(finding['rule'].get('severity', 0))
        severity_counts[severity_name] += 1

    # Get unique rules
    unique_rules = set(finding['rule']['rule_uuid'] for finding in scan_results)
    total_rules = len(unique_rules)

    # Count by platform, provider, and service
    platforms = Counter(finding['rule']['platform'] for finding in scan_results)
    providers = Counter(finding['rule']['cloud_provider'] for finding in scan_results)
    services = Counter(finding['rule']['service'] for finding in scan_results)

    # Get date range
    dates = [finding['last_detected'] for finding in scan_results if finding.get('last_detected')]
    if dates:
        date_objects = [datetime.fromisoformat(d.replace('Z', '+00:00')) for d in dates]
        min_date = min(date_objects).strftime('%B %d, %Y')
        max_date = max(date_objects).strftime('%B %d, %Y')
        report_generated = datetime.now().strftime('%B %d, %Y at %I:%M %p UTC')
    else:
        min_date = max_date = datetime.now().strftime('%B %d, %Y')
        report_generated = datetime.now().strftime('%B %d, %Y at %I:%M %p UTC')

    # Group violations by project
    violations_by_project = defaultdict(list)
    for finding in scan_results:
        violations_by_project[finding['project_name']].append(finding)

    # Count top violations
    rule_counts = Counter()
    for finding in scan_results:
        rule_key = (
            finding['rule']['rule_name'],
            finding['rule']['platform'],
            finding['rule']['service'],
            get_severity_name(finding['rule'].get('severity', 0))
        )
        rule_counts[rule_key] += 1

    # Falcon Console URLs
    console_base_url = get_falcon_console_url(region)
    critical_url = get_falcon_console_url(region, "filter=severity%3A%27Critical%27&page=1")
    high_url = get_falcon_console_url(region, "filter=severity%3A%27High%27&page=1")
    medium_url = get_falcon_console_url(region, "filter=severity%3A%27Medium%27&page=1")
    low_url = get_falcon_console_url(region, "filter=severity%3A%27Low%27&page=1")

    # Generate HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CrowdStrike Falcon Cloud Security - IaC Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0D1117 0%, #161B22 100%);
            color: #C9D1D9;
            line-height: 1.6;
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{ max-width: 1400px; margin: 0 auto; }}

        /* Header with CrowdStrike Branding */
        .header {{
            background: linear-gradient(135deg, #E01F27 0%, #B01419 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 8px 16px rgba(224, 31, 39, 0.3);
            position: relative;
            overflow: hidden;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            border-radius: 50%;
        }}

        .header-content {{ position: relative; z-index: 1; }}

        .logo-section {{
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }}

        .logo {{
            font-size: 48px;
            margin-right: 15px;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.3));
        }}

        .header h1 {{
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}

        .header .subtitle {{
            font-size: 18px;
            opacity: 0.95;
            font-weight: 400;
        }}

        .pipeline-badge {{
            display: inline-flex;
            align-items: center;
            background: rgba(255,255,255,0.15);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 13px;
            margin-top: 15px;
            backdrop-filter: blur(10px);
        }}

        .pipeline-badge strong {{ margin-left: 5px; }}

        /* Executive Summary */
        .executive-summary {{
            background: #161B22;
            padding: 30px;
            border-radius: 12px;
            border-left: 5px solid #E01F27;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}

        .executive-summary h2 {{
            color: #E01F27;
            font-size: 24px;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #0D1117 0%, #1C2128 100%);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #30363D;
            transition: transform 0.2s, box-shadow 0.2s;
            text-decoration: none;
            color: inherit;
            display: block;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(224, 31, 39, 0.2);
            cursor: pointer;
        }}

        .stat-label {{
            color: #8B949E;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            font-weight: 600;
        }}

        .stat-value {{
            font-size: 32px;
            font-weight: 700;
            color: #C9D1D9;
        }}

        .stat-value.critical {{ color: #E01F27; }}

        /* Severity Cards */
        .severity-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .severity-card {{
            background: #161B22;
            padding: 30px;
            border-radius: 12px;
            border-left: 5px solid;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            transition: transform 0.2s, box-shadow 0.3s;
            text-decoration: none;
            color: inherit;
            display: block;
            position: relative;
        }}

        .severity-card:hover {{
            transform: translateY(-6px);
            box-shadow: 0 8px 20px rgba(224, 31, 39, 0.4);
            cursor: pointer;
        }}

        .severity-card::after {{
            content: '→ View in Console';
            position: absolute;
            bottom: 15px;
            right: 20px;
            font-size: 11px;
            color: #8B949E;
            opacity: 0;
            transition: opacity 0.2s;
        }}

        .severity-card:hover::after {{
            opacity: 1;
        }}

        .severity-card.critical {{ border-left-color: #E01F27; }}
        .severity-card.high {{ border-left-color: #FF3D3D; }}
        .severity-card.medium {{ border-left-color: #FF6B00; }}
        .severity-card.low {{ border-left-color: #FFC107; }}

        .severity-card h3 {{
            color: #8B949E;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            font-weight: 600;
        }}

        .severity-card .value {{
            font-size: 48px;
            font-weight: 700;
            color: #C9D1D9;
            line-height: 1;
            margin-bottom: 10px;
        }}

        .severity-card .subtext {{
            color: #8B949E;
            font-size: 12px;
        }}

        /* Section Styling */
        .section {{
            background: #161B22;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}

        .section h2 {{
            color: #E01F27;
            font-size: 22px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #30363D;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        /* Table Styling */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 13px;
        }}

        th {{
            background: #0D1117;
            color: #8B949E;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 1px;
            border-bottom: 2px solid #30363D;
        }}

        td {{
            padding: 15px;
            border-bottom: 1px solid #21262D;
        }}

        tr:hover {{ background: rgba(224, 31, 39, 0.05); }}

        /* Severity Badges */
        .severity-badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-critical {{ background: #E01F27; color: white; }}
        .severity-high {{ background: #FF3D3D; color: white; }}
        .severity-medium {{ background: #FF6B00; color: white; }}
        .severity-low {{ background: #FFC107; color: #000; }}

        /* Platform Badge */
        .platform-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            background: #238636;
            color: white;
        }}

        /* Footer */
        .footer {{
            background: #0D1117;
            padding: 30px;
            border-radius: 12px;
            text-align: center;
            color: #6E7681;
            margin-top: 40px;
            border-top: 3px solid #E01F27;
        }}

        .footer p {{ margin: 8px 0; font-size: 13px; }}
        .footer strong {{ color: #C9D1D9; }}
        .footer a {{ color: #58A6FF; text-decoration: none; }}
        .footer a:hover {{ text-decoration: underline; }}

        .cs-logo-text {{
            font-size: 18px;
            color: #E01F27;
            font-weight: 700;
            margin-bottom: 10px;
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .header h1 {{ font-size: 28px; }}
            .severity-section {{ grid-template-columns: 1fr; }}
            .summary-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- CrowdStrike Branded Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo-section">
                    <div class="logo">🛡️</div>
                    <div>
                        <h1>CrowdStrike Falcon Cloud Security</h1>
                        <div class="subtitle">Infrastructure as Code Security Scan Report</div>
                    </div>
                </div>
                <div class="pipeline-badge">
                    🔄 <strong>Pipeline:</strong> {pipeline_name} | <strong>Build:</strong> #{build_number}
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <a href="{console_base_url}" target="_blank" class="stat-card">
                    <div class="stat-label">Total Violations</div>
                    <div class="stat-value critical">{total_violations}</div>
                </a>
                <a href="{console_base_url}" target="_blank" class="stat-card">
                    <div class="stat-label">Projects Scanned</div>
                    <div class="stat-value">{total_projects}</div>
                </a>
                <a href="{console_base_url}" target="_blank" class="stat-card">
                    <div class="stat-label">Files Affected</div>
                    <div class="stat-value">{total_files}</div>
                </a>
                <a href="{console_base_url}" target="_blank" class="stat-card">
                    <div class="stat-label">Rules Violated</div>
                    <div class="stat-value">{total_rules}</div>
                </a>
            </div>
        </div>

        <!-- Severity Cards -->
        <div class="severity-section">
            <a href="{critical_url}" target="_blank" class="severity-card critical">
                <h3>🔴 Critical Severity</h3>
                <div class="value">{severity_counts.get('critical', 0)}</div>
                <div class="subtext">Requires immediate remediation</div>
            </a>
            <a href="{high_url}" target="_blank" class="severity-card high">
                <h3>🟠 High Severity</h3>
                <div class="value">{severity_counts.get('high', 0)}</div>
                <div class="subtext">Must be addressed soon</div>
            </a>
            <a href="{medium_url}" target="_blank" class="severity-card medium">
                <h3>🟡 Medium Severity</h3>
                <div class="value">{severity_counts.get('medium', 0)}</div>
                <div class="subtext">Should be fixed</div>
            </a>
            <a href="{low_url}" target="_blank" class="severity-card low">
                <h3>🟢 Low Severity</h3>
                <div class="value">{severity_counts.get('low', 0) + severity_counts.get('informational', 0)}</div>
                <div class="subtext">Minor issues</div>
            </a>
        </div>

        <!-- Scan Coverage -->
        <div class="section">
            <h2>📈 Scan Coverage & Statistics</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Count</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>IaC Platforms</strong></td>
                        <td><strong>{len(platforms)}</strong></td>
                        <td>{', '.join(f'{{k}}: {{v}}' for k, v in platforms.most_common())}</td>
                    </tr>
                    <tr>
                        <td><strong>Cloud Providers</strong></td>
                        <td><strong>{len(providers)}</strong></td>
                        <td>{', '.join(f'{{k}}: {{v}}' for k, v in providers.most_common())}</td>
                    </tr>
                    <tr>
                        <td><strong>Cloud Services</strong></td>
                        <td><strong>{len(services)}</strong></td>
                        <td>{', '.join(f'{{k}}: {{v}}' for k, v in services.most_common(10))}</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Top Violations -->
        <div class="section">
            <h2>🚨 Top 20 Most Common Violations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Rule Name</th>
                        <th>Platform</th>
                        <th>Service</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
"""

    # Add top 20 violations
    for (rule_name, platform, service, severity), count in rule_counts.most_common(20):
        html_content += f"""
                    <tr>
                        <td><span class="severity-badge severity-{severity}">{severity.upper()}</span></td>
                        <td><strong>{rule_name}</strong></td>
                        <td><span class="platform-badge">{platform}</span></td>
                        <td>{service}</td>
                        <td><strong>{count}</strong></td>
                    </tr>
"""

    html_content += """
                </tbody>
            </table>
        </div>

        <!-- Projects Summary -->
        <div class="section">
            <h2>📁 Projects Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Project Name</th>
                        <th>Total Violations</th>
                        <th>Files Affected</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                    </tr>
                </thead>
                <tbody>
"""

    # Add project summaries
    for project_name, findings in violations_by_project.items():
        project_files = set(f['file_name'] for f in findings)
        project_severities = Counter()
        for f in findings:
            sev = get_severity_name(f['rule'].get('severity', 0))
            project_severities[sev] += 1

        html_content += f"""
                    <tr>
                        <td><strong>{project_name}</strong></td>
                        <td><strong>{len(findings)}</strong></td>
                        <td>{len(project_files)}</td>
                        <td>{project_severities.get('critical', 0)}</td>
                        <td>{project_severities.get('high', 0)}</td>
                        <td>{project_severities.get('medium', 0)}</td>
                        <td>{project_severities.get('low', 0) + project_severities.get('informational', 0)}</td>
                    </tr>
"""

    html_content += f"""
                </tbody>
            </table>
        </div>

        <!-- CrowdStrike Footer -->
        <div class="footer">
            <div class="cs-logo-text">🛡️ CROWDSTRIKE FALCON CLOUD SECURITY</div>
            <p><strong>Falcon Cloud Security (FCS)</strong> - Infrastructure as Code Security</p>
            <p>Pre-Deployment IaC Scanning | Terraform | CloudFormation | Kubernetes</p>
            <p style="margin-top: 15px;">Pipeline: <strong>{pipeline_name}</strong> | Build: <strong>#{build_number}</strong> | Build ID: <strong>{build_id}</strong></p>
            <p>Report Generated: <strong>{report_generated}</strong> | Scan Period: <strong>{min_date} - {max_date}</strong></p>
            <p style="margin-top: 15px;"><a href="{console_base_url}" target="_blank">🔗 View Full Report in Falcon Console</a></p>
            <p style="margin-top: 15px; font-size: 11px;">We Stop Breaches | <a href="https://www.crowdstrike.com" target="_blank">www.crowdstrike.com</a></p>
        </div>
    </div>
</body>
</html>
"""

    # Write to file
    with open(output_file, 'w') as f:
        f.write(html_content)

    print(f"✓ Dark-themed interactive HTML report generated: {output_file}")
    print(f"  Total violations: {total_violations}")
    print(f"  Projects: {total_projects}")
    print(f"  Files: {total_files}")
    print(f"  Critical: {severity_counts.get('critical', 0)}")
    print(f"  High: {severity_counts.get('high', 0)}")
    print(f"  Medium: {severity_counts.get('medium', 0)}")
    print(f"  Low: {severity_counts.get('low', 0) + severity_counts.get('informational', 0)}")
    print(f"  Theme: Dark")
    print(f"  Falcon Console links: Enabled")

    return True

def main():
    """Main function"""
    import sys

    # Default input and output files
    input_file = '/Users/tmilewicz/fcs_iac_scan_results_latest.json'
    output_file = '/Users/tmilewicz/fcs_iac_dark_report_interactive.html'

    # Get environment variables for pipeline info
    pipeline_name = os.environ.get('JOB_NAME', 'IaC Security Scan')
    build_number = os.environ.get('BUILD_NUMBER', 'N/A')
    build_id = os.environ.get('BUILD_ID', 'N/A')
    region = os.environ.get('FALCON_REGION', 'us-1')

    # Allow command line arguments
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    if len(sys.argv) > 3:
        region = sys.argv[3]

    print("=" * 80)
    print("CrowdStrike IaC Scan - Dark Theme Interactive HTML Report Generator")
    print("=" * 80)
    print(f"\nInput file:  {input_file}")
    print(f"Output file: {output_file}")
    print(f"Region:      {region}")
    print(f"Pipeline:    {pipeline_name}")
    print(f"Build:       #{build_number}\n")

    # Load scan results
    scan_results = load_scan_results(input_file)

    if not scan_results:
        print("\n✗ No scan results found or unable to load file")
        sys.exit(1)

    # Generate report
    success = generate_html_report(
        scan_results,
        output_file,
        pipeline_name=pipeline_name,
        build_number=build_number,
        build_id=build_id,
        region=region
    )

    if success:
        print("\n" + "=" * 80)
        print("Report Generation Complete")
        print("=" * 80)
        sys.exit(0)
    else:
        print("\n✗ Report generation failed")
        sys.exit(1)
'''

                        // Execute with Docker Python
                        sh '''
                            docker run --rm \
                                -v "$WORKSPACE:/workspace" \
                                -w /workspace \
                                -e BUILD_NUMBER="$BUILD_NUMBER" \
                                -e JOB_NAME="$JOB_NAME" \
                                -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
                                -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
                                -e FALCON_REGION="$FALCON_REGION" \
                                python:3.9-alpine python3 generate_iac_report.py || echo "Report generation had issues"
                        '''

                        publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                                    reportDir: '.', reportFiles: 'iac_assessment_report.html',
                                    reportName: 'IaC Assessment Report'])
                    }
                }
            }
        }

        stage('Test with Snyk') {
            steps {
                script {
                    snykSecurity failOnIssues: false, severity: 'critical', snykInstallation: 'snyk-manual', snykTokenId: 'SNYK'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    sh '''
                        cat > Dockerfile << 'DOCKEREOF'
FROM node:18-alpine
RUN apk add --no-cache dumb-init curl wget
WORKDIR /juice-shop
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p logs uploads && chmod 755 logs uploads
USER node
EXPOSE 3000
CMD ["npm", "start"]
DOCKEREOF
                        docker build -t juice-shop:latest .
                    '''
                }
            }
        }

        stage('Falcon Cloud Security Image Scan') {
            steps {
                script {
                    try {
                        withCredentials([usernameColonPassword(credentialsId: 'CRWD', variable: 'FALCON_CREDENTIALS')]) {
                            crowdStrikeSecurity imageName: 'juice-shop', imageTag: 'latest', enforce: false, timeout: 60
                        }
                    } catch (Exception e) {
                        echo "Image scan had issues: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    script {
                        sh '''
                            # Find the most recent CrowdStrike assessment report
                            echo "Looking for CrowdStrike scan files..."

                            # Find the newest crwds_assessment_report_*.json file
                            LATEST_REPORT=$(find . -maxdepth 1 -name "crwds_assessment_report_*.json" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2)

                            if [ -n "$LATEST_REPORT" ] && [ -f "$LATEST_REPORT" ]; then
                                echo "✅ Found latest CrowdStrike report: $LATEST_REPORT"
                                cp "$LATEST_REPORT" container_scan.json
                            elif [ -f "crowdstrike_scan_report.json" ]; then
                                echo "Found: crowdstrike_scan_report.json"
                                cp crowdstrike_scan_report.json container_scan.json
                            elif [ -f "report.json" ]; then
                                echo "Found: report.json"
                                cp report.json container_scan.json
                            else
                                echo "❌ No scan report found, creating empty file"
                                echo '{"Vulnerabilities": []}' > container_scan.json
                            fi

                            echo "Container scan file details:"
                            ls -lh container_scan.json
                            echo "First 500 characters:"
                            head -c 500 container_scan.json
                        '''

                        // Write Image Assessment Python script
                        writeFile file: 'generate_image_report.py', text: '''import json
import os
from datetime import datetime
from collections import Counter

vulnerabilities = []
if os.path.exists("container_scan.json"):
    with open("container_scan.json") as f:
        data = json.load(f)
    if "Vulnerabilities" in data:
        raw = data["Vulnerabilities"]
        if raw and isinstance(raw, list) and len(raw) > 0:
            if isinstance(raw[0], dict) and "Vulnerability" in raw[0]:
                vulnerabilities = [v["Vulnerability"] for v in raw if "Vulnerability" in v]
            else:
                vulnerabilities = raw

remediable = sum(1 for v in vulnerabilities if "Remediation" in v and v["Remediation"] and v["Remediation"] not in ["", {}, [], None, "none"])

severity_counts = Counter()
for v in vulnerabilities:
    sev = "UNKNOWN"
    if "Details" in v:
        cps = v.get("Details", {}).get("cps_rating", {}).get("CurrentRating", {})
        if "Rating" in cps:
            sev = cps["Rating"].upper()
    severity_counts[sev] += 1

total = len(vulnerabilities)
crit_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
repo = os.environ.get("CONTAINER_REPO", "juice-shop")
tag = os.environ.get("CONTAINER_TAG", "latest")
job = os.environ.get("JOB_NAME", "N/A")
build = os.environ.get("BUILD_NUMBER", "N/A")
report_time = datetime.now().strftime("%B %d, %Y at %I:%M %p UTC")

html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>CrowdStrike Container Assessment</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Arial,sans-serif;background:#000;color:#fff;padding:0;min-height:100vh}
.brand-bar{background:linear-gradient(135deg,#E01F27 0%,#B71C1C 100%);height:8px}
.container{max-width:1400px;margin:0 auto;padding:30px}
.header{background:linear-gradient(135deg,#1a1a1a 0%,#0a0a0a 100%);color:white;padding:40px;border-radius:8px;margin-bottom:30px;border:1px solid #E01F27;box-shadow:0 4px 20px rgba(224,31,39,0.3)}
.header-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.logo{font-size:28px;font-weight:700;color:#E01F27;letter-spacing:1px}
.logo-text{color:#fff;font-size:20px;margin-left:10px}
.falcon-icon{font-size:36px;margin-right:10px}
.header h1{font-size:32px;margin-bottom:15px;color:#fff;font-weight:600}
.header-meta{color:#aaa;font-size:14px;margin-top:10px}
.header-meta strong{color:#E01F27}
.image-info{background:#0d0d0d;padding:15px;border-radius:6px;margin-top:15px;border-left:3px solid #E01F27}
.image-info code{color:#61AFEF;font-family:monospace;font-size:16px}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:25px;margin-bottom:30px}
.stat-card{background:linear-gradient(135deg,#1a1a1a 0%,#0d0d0d 100%);padding:30px;border-radius:8px;border-left:5px solid #E01F27;box-shadow:0 2px 10px rgba(0,0,0,0.5);transition:transform 0.2s}
.stat-card:hover{transform:translateY(-5px);box-shadow:0 4px 20px rgba(224,31,39,0.4)}
.stat-label{color:#999;font-size:13px;margin-bottom:12px;text-transform:uppercase;letter-spacing:1px;font-weight:600}
.stat-value{font-size:48px;font-weight:700;color:#fff;text-shadow:0 0 10px rgba(224,31,39,0.3)}
.stat-card.critical .stat-value{color:#FF3D3D}
.stat-card.high .stat-value{color:#E01F27}
.stat-card.remediate .stat-value{color:#4EC9B0}
.section{background:#1a1a1a;padding:30px;border-radius:8px;margin-bottom:25px;border:1px solid #333;box-shadow:0 2px 10px rgba(0,0,0,0.3)}
.section h2{color:#E01F27;margin-bottom:25px;font-size:24px;font-weight:600;border-bottom:2px solid #E01F27;padding-bottom:10px}
table{width:100%;border-collapse:collapse}
th,td{padding:16px;text-align:left;border-bottom:1px solid #333}
th{background:#0d0d0d;color:#E01F27;font-weight:600;text-transform:uppercase;font-size:12px;letter-spacing:1px}
tr:hover{background:#222}
.severity-critical{color:#FF3D3D;font-weight:700;text-shadow:0 0 5px rgba(255,61,61,0.3)}
.severity-high{color:#E01F27;font-weight:700}
.severity-medium{color:#FFB84D;font-weight:600}
.severity-low{color:#4EC9B0}
.remediate-yes{color:#4EC9B0;font-weight:600}
.remediate-no{color:#888}
.footer{text-align:center;margin-top:50px;padding:30px;color:#666;font-size:13px;border-top:1px solid #333}
.footer strong{color:#E01F27;font-size:15px}
.powered-by{margin-top:10px;color:#888;font-size:11px}
</style></head><body>
<div class="brand-bar"></div>
<div class="container">
<div class="header">
<div class="header-top">
<div><span class="falcon-icon">🦅</span><span class="logo">CROWDSTRIKE</span><span class="logo-text">Falcon Cloud Security</span></div>
</div>
<h1>Container Image Vulnerability Assessment</h1>
<div class="image-info"><code>""" + repo + ":" + tag + """</code></div>
<div class="header-meta">
<strong>Job:</strong> """ + job + """ | <strong>Build:</strong> #""" + build + """<br>
<strong>Generated:</strong> """ + report_time + """
</div>
</div>
<div class="summary-grid">
<div class="stat-card"><div class="stat-label">Total Vulnerabilities</div><div class="stat-value">""" + str(total) + """</div></div>
<div class="stat-card high"><div class="stat-label">Critical + High</div><div class="stat-value">""" + str(crit_high) + """</div></div>
<div class="stat-card remediate"><div class="stat-label">Remediable</div><div class="stat-value">""" + str(remediable) + """</div></div>
</div>
<div class="section"><h2>📊 Severity Distribution</h2><table>
<thead><tr><th>Severity Level</th><th>Count</th><th>Percentage</th></tr></thead>
<tbody>
<tr><td class="severity-critical">● CRITICAL</td><td>""" + str(severity_counts.get("CRITICAL", 0)) + """</td><td>""" + str(round(severity_counts.get("CRITICAL", 0) / max(total, 1) * 100, 1)) + """%</td></tr>
<tr><td class="severity-high">● HIGH</td><td>""" + str(severity_counts.get("HIGH", 0)) + """</td><td>""" + str(round(severity_counts.get("HIGH", 0) / max(total, 1) * 100, 1)) + """%</td></tr>
<tr><td class="severity-medium">● MEDIUM</td><td>""" + str(severity_counts.get("MEDIUM", 0)) + """</td><td>""" + str(round(severity_counts.get("MEDIUM", 0) / max(total, 1) * 100, 1)) + """%</td></tr>
<tr><td class="severity-low">● LOW</td><td>""" + str(severity_counts.get("LOW", 0)) + """</td><td>""" + str(round(severity_counts.get("LOW", 0) / max(total, 1) * 100, 1)) + """%</td></tr>
</tbody>
</table></div>
<div class="section"><h2>🔍 Top 20 Critical Vulnerabilities</h2><table>
<thead><tr><th>Severity</th><th>CVE ID</th><th>Package</th><th>Remediable</th></tr></thead><tbody>"""

sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

def get_sev(v):
    if "Details" in v:
        cps = v.get("Details", {}).get("cps_rating", {}).get("CurrentRating", {})
        if "Rating" in cps:
            return cps["Rating"].upper()
    return "UNKNOWN"

sorted_v = sorted(vulnerabilities, key=lambda x: sev_order.get(get_sev(x), 4))[:20]

for v in sorted_v:
    sev = get_sev(v)
    cve = v.get("CVEID", "N/A")
    pkg = "Unknown"
    if "Product" in v:
        p = v["Product"]
        pkg = p.get("PackageSource", "Unknown") if isinstance(p, dict) else str(p)
    rem = "Remediation" in v and v["Remediation"] and v["Remediation"] not in ["", {}, [], None, "none"]
    rem_text = '<span class="remediate-yes">✓ Yes</span>' if rem else '<span class="remediate-no">✗ No</span>'
    html += '<tr><td class="severity-' + sev.lower() + '">● ' + sev + '</td><td>' + cve + '</td><td>' + pkg + '</td><td>' + rem_text + '</td></tr>'

html += """</tbody></table></div>
<div class="footer">
<strong>🦅 CrowdStrike Falcon Cloud Security</strong>
<div class="powered-by">Powered by CrowdStrike Threat Intelligence | © 2026 CrowdStrike, Inc.</div>
</div>
</div></body></html>"""

with open("image_assessment_report.html", "w") as f:
    f.write(html)
print("✅ Image Report generated")
'''

                        sh '''
                            docker run --rm \
                                -v "$WORKSPACE:/workspace" \
                                -w /workspace \
                                -e CONTAINER_REPO="$CONTAINER_REPO" \
                                -e CONTAINER_TAG="$CONTAINER_TAG" \
                                -e BUILD_NUMBER="$BUILD_NUMBER" \
                                -e JOB_NAME="$JOB_NAME" \
                                python:3.9-alpine python3 generate_image_report.py || echo "Report generation had issues"
                        '''

                        publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                                    reportDir: '.', reportFiles: 'image_assessment_report.html',
                                    reportName: 'Image Assessment Report'])
                        archiveArtifacts artifacts: 'container_scan.json', allowEmptyArchive: true
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                script {
                    sh 'docker rm -f juice-shop || true'
                    sh 'docker run -d -p 3000:3000 --name juice-shop juice-shop:latest'
                    sleep(time: 10, unit: 'SECONDS')
                    echo "✅ Juice Shop deployed on http://localhost:3000"
                }
            }
        }
    }

    post {
        always {
            sh 'docker ps -a --filter name=juice-shop || true'
        }
        success {
            echo '✅ Pipeline completed successfully!'
            echo '📊 Check sidebar for IaC and Image Assessment reports'
        }
        failure {
            echo '❌ Pipeline failed'
        }
    }
}
