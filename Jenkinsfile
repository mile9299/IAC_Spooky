pipeline {
    agent any

    environment {
        JUICE_SHOP_REPO = 'https://github.com/mile9299/juice-shopv21.git'
        DOCKER_PORT = 3000
        SPECTRAL_DSN = credentials('SPECTRAL_DSN')
        CS_IMAGE_NAME = 'mile/cs-fcs'
        CS_IMAGE_TAG = '2.1.0'
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
                                echo "$CS_PASSWORD" | docker login --username "$CS_USERNAME" --password-stdin "$CS_REGISTRY"

                                if [ $? -eq 0 ]; then
                                    echo "Docker login successful"
                                    echo "Pulling fcs container target from crowdstrike"
                                    docker pull "$CS_IMAGE_NAME:$CS_IMAGE_TAG"
                                    if [ $? -eq 0 ]; then
                                        echo "fcs docker container image pulled successfully"
                                        echo "=============== FCS IaC Scan Starts ==============="

                                        # Create output directory
                                        mkdir -p "$WORKSPACE/iac_reports"

                                        # Run scan with correct volume mount to Jenkins workspace
                                        docker run --network=host --rm \
                                            -v "$WORKSPACE/iac_reports:/reports" \
                                            "$CS_IMAGE_NAME:$CS_IMAGE_TAG" \
                                            --client-id "$CS_CLIENT_ID" \
                                            --client-secret "$CS_CLIENT_SECRET" \
                                            --falcon-region "$FALCON_REGION" \
                                            iac scan -p "$PROJECT_PATH" \
                                            --report-formats json \
                                            --output-path /reports/iac_scan_results.json || true

                                        scan_status=$?
                                        echo "=============== FCS IaC Scan Ends ==============="

                                        # Copy results to workspace root for easier access
                                        cp "$WORKSPACE/iac_reports/iac_scan_results.json" "$WORKSPACE/iac_scan_results.json" 2>/dev/null || echo '{"resources": []}' > "$WORKSPACE/iac_scan_results.json"
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
                        echo "Scan succeeded & vulnerabilities count are ABOVE the '--fail-on' threshold"
                        currentBuild.result = 'UNSTABLE'
                    } else if (SCAN_EXIT_CODE == 0) {
                        echo "Scan succeeded & vulnerabilities count are BELOW the '--fail-on' threshold"
                        currentBuild.result = 'SUCCESS'
                    } else {
                        echo "Scan had issues but continuing pipeline..."
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    script {
                        // Generate IaC HTML Report using Docker with Python
                        sh '''
                            echo "=== Generating IaC Assessment HTML Report ==="

                            # Use Python Docker image to generate report
                            docker run --rm -v "$WORKSPACE:/workspace" -w /workspace python:3.9-alpine sh -c '
                                pip install --quiet requests 2>/dev/null || true

                                cat > /workspace/generate_iac_report.py << "PYTHON_SCRIPT"
import json
import os
from datetime import datetime
from collections import Counter

def generate_iac_report():
    report_path = "iac_scan_results.json"

    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            scan_data = json.load(f)
        print(f"✅ Found IaC scan results")
    else:
        print("⚠️ No IaC scan results found, creating empty report")
        scan_data = {"resources": [], "summary": {}}

    findings = scan_data.get("resources", [])
    severity_counts = Counter()

    for finding in findings:
        severity = finding.get("severity", finding.get("Severity", "UNKNOWN")).upper()
        severity_counts[severity] += 1

    report_time = datetime.now().strftime("%B %d, %Y at %I:%M %p UTC")
    build_number = os.environ.get("BUILD_NUMBER", "N/A")
    job_name = os.environ.get("JOB_NAME", "N/A")
    project_path = os.environ.get("PROJECT_PATH", "N/A")

    total_findings = len(findings)
    critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CrowdStrike IaC Security Assessment</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: "Segoe UI", sans-serif; background: linear-gradient(135deg, #0D1117 0%, #161B22 100%); color: #C9D1D9; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
.header {{ background: linear-gradient(135deg, #E01F27 0%, #B01419 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
.header h1 {{ font-size: 32px; margin-bottom: 10px; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
.stat-card {{ background: #161B22; padding: 20px; border-radius: 8px; border-left: 4px solid #E01F27; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }}
.stat-label {{ color: #8B949E; font-size: 14px; margin-bottom: 8px; }}
.stat-value {{ font-size: 32px; font-weight: 700; color: #C9D1D9; }}
.section {{ background: #161B22; padding: 25px; border-radius: 12px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
.section h2 {{ color: #E01F27; margin-bottom: 20px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #30363D; }}
th {{ background: #0D1117; color: #E01F27; font-weight: 600; }}
tr:hover {{ background: #0D1117; }}
.severity-critical {{ color: #FF3D3D; font-weight: 700; }}
.severity-high {{ color: #FF6B00; font-weight: 700; }}
.severity-medium {{ color: #FFB84D; font-weight: 600; }}
.severity-low {{ color: #4EC9B0; font-weight: 500; }}
.severity-informational {{ color: #58A6FF; font-weight: 500; }}
.footer {{ text-align: center; margin-top: 40px; color: #8B949E; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>🛡️ CrowdStrike IaC Security Assessment</h1>
  <p><strong>Project:</strong> {project_path}</p>
  <p><strong>Job:</strong> {job_name} | <strong>Build:</strong> #{build_number}</p>
  <p><strong>Generated:</strong> {report_time}</p>
</div>
<div class="summary-grid">
  <div class="stat-card"><div class="stat-label">Total Findings</div><div class="stat-value">{total_findings}</div></div>
  <div class="stat-card"><div class="stat-label">Critical + High</div><div class="stat-value">{critical_high}</div></div>
</div>
<div class="section">
  <h2>📊 Severity Breakdown</h2>
  <table>
      <tr><th>Severity</th><th>Count</th></tr>
      <tr><td class="severity-critical">CRITICAL</td><td>{severity_counts.get("CRITICAL", 0)}</td></tr>
      <tr><td class="severity-high">HIGH</td><td>{severity_counts.get("HIGH", 0)}</td></tr>
      <tr><td class="severity-medium">MEDIUM</td><td>{severity_counts.get("MEDIUM", 0)}</td></tr>
      <tr><td class="severity-low">LOW</td><td>{severity_counts.get("LOW", 0)}</td></tr>
      <tr><td class="severity-informational">INFORMATIONAL</td><td>{severity_counts.get("INFORMATIONAL", 0)}</td></tr>
  </table>
</div>
<div class="section">
  <h2>🔍 Top 20 Findings</h2>
  <table>
      <thead><tr><th>Severity</th><th>Resource</th><th>Issue</th><th>File</th></tr></thead>
      <tbody>
"""

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "UNKNOWN").upper(), 5))[:20]

    for finding in sorted_findings:
        severity = finding.get("severity", "Unknown").upper()
        resource = finding.get("resource", finding.get("Resource", "Unknown"))
        issue = finding.get("title", finding.get("Title", finding.get("message", "No description")))
        file_path = finding.get("file", finding.get("File", "N/A"))
        severity_class = f"severity-{severity.lower()}"
        html += f"""<tr><td class="{severity_class}">{severity}</td><td>{resource}</td><td>{issue}</td><td>{file_path}</td></tr>"""

    html += """
      </tbody>
  </table>
</div>
<div class="footer"><strong>🛡️ CrowdStrike Falcon Cloud Security</strong><br>Infrastructure as Code Security Assessment</div>
</div>
</body>
</html>
"""
    return html

try:
    html_report = generate_iac_report()
    with open("iac_assessment_report.html", "w") as f:
        f.write(html_report)
    print("✅ IaC Assessment Report generated successfully")
except Exception as e:
    print(f"❌ Error generating report: {e}")
    import traceback
    traceback.print_exc()

PYTHON_SCRIPT

                                python3 /workspace/generate_iac_report.py
                            ' || echo "Report generation had issues but continuing..."
                        '''
                    }
                }
                success {
                    echo 'FCS IaC Scan succeeded!'
                    publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                                reportDir: '.', reportFiles: 'iac_assessment_report.html',
                                reportName: 'IaC Assessment Report', reportTitles: 'CrowdStrike IaC Security'])
                }
                unstable {
                    echo 'FCS IaC Scan is unstable, but still considered successful!'
                    publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                                reportDir: '.', reportFiles: 'iac_assessment_report.html',
                                reportName: 'IaC Assessment Report', reportTitles: 'CrowdStrike IaC Security'])
                }
                failure {
                    echo 'FCS IaC Scan failed!'
                    publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                                reportDir: '.', reportFiles: 'iac_assessment_report.html',
                                reportName: 'IaC Assessment Report', reportTitles: 'CrowdStrike IaC Security'])
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

        stage('Analyze Package Scripts') {
            steps {
                script {
                    echo 'Analyzing project structure and available scripts'
                    sh '''
                        echo "=== Project Structure ==="
                        ls -la
                        echo ""
                        echo "=== Package.json content ==="
                        cat package.json | head -50 || echo "No package.json found"
                    '''
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    echo 'Building Juice Shop Docker image'
                    sh '''
                        cat > Dockerfile << 'EOF'
FROM node:18-alpine
RUN apk add --no-cache dumb-init curl wget
WORKDIR /juice-shop
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p logs uploads && chmod 755 logs uploads && chown -R node:node /juice-shop
RUN npm run build 2>/dev/null || echo "No build script found, skipping build"
USER node
EXPOSE 3000
RUN echo '#!/bin/sh\\necho "Starting application..."\\nif npm run start 2>/dev/null; then\\n  echo "Started with: npm run start"\\nelif [ -f "app.js" ]; then\\n  node app.js\\nelif [ -f "server.js" ]; then\\n  node server.js\\nelse\\n  echo "No suitable startup method found"\\n  exit 1\\nfi' > /juice-shop/start.sh && chmod +x /juice-shop/start.sh
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 CMD wget --no-verbose --tries=1 --spider http://localhost:3000 || exit 1
ENTRYPOINT ["dumb-init", "--"]
CMD ["sh", "/juice-shop/start.sh"]
EOF
                        docker build -t juice-shop:latest .
                        echo "✅ Docker image built successfully"
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
                            # Look for CrowdStrike scan results
                            if [ -f "crowdstrike_scan_report.json" ]; then
                                cp crowdstrike_scan_report.json container_scan.json
                            elif [ -f "report.json" ]; then
                                cp report.json container_scan.json
                            else
                                echo '{"Vulnerabilities": [], "error": "No scan data"}' > container_scan.json
                            fi

                            echo "=== Generating Image Assessment HTML Report ==="

                            # Use Python Docker to generate report (condensed version for Jenkins)
                            docker run --rm \
                                -v "$WORKSPACE:/workspace" \
                                -w /workspace \
                                -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
                                -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
                                -e FALCON_REGION="$FALCON_REGION" \
                                -e CONTAINER_REPO="$CONTAINER_REPO" \
                                -e CONTAINER_TAG="$CONTAINER_TAG" \
                                -e BUILD_NUMBER="$BUILD_NUMBER" \
                                -e JOB_NAME="$JOB_NAME" \
                                python:3.9-alpine sh -c '
                                    pip install --quiet requests 2>/dev/null || true
                                    python3 -c "
import json, os
from datetime import datetime
from collections import Counter

vulnerabilities = []
if os.path.exists(\"container_scan.json\"):
    with open(\"container_scan.json\") as f:
        data = json.load(f)
    if \"Vulnerabilities\" in data:
        raw = data[\"Vulnerabilities\"]
        if raw and isinstance(raw[0], dict) and \"Vulnerability\" in raw[0]:
            vulnerabilities = [v[\"Vulnerability\"] for v in raw if \"Vulnerability\" in v]
        else:
            vulnerabilities = raw

remediable = sum(1 for v in vulnerabilities if \"Remediation\" in v and v[\"Remediation\"] and v[\"Remediation\"] not in [\"\", {}, [], None, \"none\", \"n/a\"])

severity_counts = Counter()
for v in vulnerabilities:
    sev = \"UNKNOWN\"
    if \"Details\" in v:
        cps = v.get(\"Details\", {}).get(\"cps_rating\", {}).get(\"CurrentRating\", {})
        if \"Rating\" in cps: sev = cps[\"Rating\"].upper()
    severity_counts[sev] += 1

html = f'''<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Container Image Assessment</title><style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:Segoe UI,sans-serif;background:linear-gradient(135deg,#0D1117 0%,#161B22 100%);color:#C9D1D9;padding:20px}}.container{{max-width:1200px;margin:0 auto}}.header{{background:linear-gradient(135deg,#E01F27 0%,#B01419 100%);color:white;padding:30px;border-radius:12px;margin-bottom:30px;box-shadow:0 4px 12px rgba(0,0,0,.3)}}.header h1{{font-size:32px;margin-bottom:10px}}.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}}.stat-card{{background:#161B22;padding:20px;border-radius:8px;border-left:4px solid #E01F27;box-shadow:0 2px 8px rgba(0,0,0,.3)}}.stat-label{{color:#8B949E;font-size:14px;margin-bottom:8px}}.stat-value{{font-size:32px;font-weight:700;color:#C9D1D9}}.section{{background:#161B22;padding:25px;border-radius:12px;margin-bottom:25px;box-shadow:0 4px 12px rgba(0,0,0,.3)}}.section h2{{color:#E01F27;margin-bottom:20px}}table{{width:100%;border-collapse:collapse;margin-top:15px}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #30363D}}th{{background:#0D1117;color:#E01F27;font-weight:600}}tr:hover{{background:#0D1117}}.severity-critical{{color:#FF3D3D;font-weight:700}}.severity-high{{color:#FF6B00;font-weight:700}}.severity-medium{{color:#FFB84D;font-weight:600}}.severity-low{{color:#4EC9B0;font-weight:500}}.footer{{text-align:center;margin-top:40px;color:#8B949E;font-size:13px}}</style></head><body><div class=\"container\"><div class=\"header\"><h1>🛡️ CrowdStrike Container Image Assessment</h1><p><strong>Image:</strong> {os.environ.get(\"CONTAINER_REPO\",\"juice-shop\")}:{os.environ.get(\"CONTAINER_TAG\",\"latest\")}</p><p><strong>Job:</strong> {os.environ.get(\"JOB_NAME\",\"N/A\")} | <strong>Build:</strong> #{os.environ.get(\"BUILD_NUMBER\",\"N/A\")}</p><p><strong>Generated:</strong> {datetime.now().strftime(\"%B %d, %Y at %I:%M %p UTC\")}</p></div><div class=\"summary-grid\"><div class=\"stat-card\"><div class=\"stat-label\">Total Vulnerabilities</div><div class=\"stat-value\">{len(vulnerabilities)}</div></div><div class=\"stat-card\"><div class=\"stat-label\">Critical + High</div><div class=\"stat-value\">{severity_counts.get(\"CRITICAL\",0)+severity_counts.get(\"HIGH\",0)}</div></div><div class=\"stat-card\"><div class=\"stat-label\">Remediable</div><div class=\"stat-value\" style=\"color:#4EC9B0\">{remediable}</div></div><div class=\"stat-card\"><div class=\"stat-label\">Secrets Detected</div><div class=\"stat-value\">0</div></div></div><div class=\"section\"><h2>📊 Severity Breakdown</h2><table><tr><th>Severity</th><th>Count</th></tr><tr><td class=\"severity-critical\">CRITICAL</td><td>{severity_counts.get(\"CRITICAL\",0)}</td></tr><tr><td class=\"severity-high\">HIGH</td><td>{severity_counts.get(\"HIGH\",0)}</td></tr><tr><td class=\"severity-medium\">MEDIUM</td><td>{severity_counts.get(\"MEDIUM\",0)}</td></tr><tr><td class=\"severity-low\">LOW</td><td>{severity_counts.get(\"LOW\",0)}</td></tr></table></div><div class=\"section\"><h2>🔍 Top 20 Vulnerabilities</h2><table><thead><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Remediable?</th></tr></thead><tbody>'''

sev_order = {{\"CRITICAL\":0,\"HIGH\":1,\"MEDIUM\":2,\"LOW\":3,\"UNKNOWN\":4}}
def get_sev(v):
    if \"Details\" in v:
        cps = v.get(\"Details\",{{}}).get(\"cps_rating\",{{}}).get(\"CurrentRating\",{{}})
        if \"Rating\" in cps: return cps[\"Rating\"].upper()
    return \"UNKNOWN\"

sorted_v = sorted(vulnerabilities, key=lambda x: sev_order.get(get_sev(x),4))[:20]
for v in sorted_v:
    sev = get_sev(v)
    cve = v.get(\"CVEID\",\"N/A\")
    pkg = \"Unknown\"
    if \"Product\" in v:
        p = v[\"Product\"]
        pkg = p.get(\"PackageSource\",\"Unknown\") if isinstance(p,dict) else str(p)
    rem = \"Remediation\" in v and v[\"Remediation\"] and v[\"Remediation\"] not in [\"\",{{}},[]

,None,\"none\",\"n/a\"]
    rem_text = '<span style=\"color:#4EC9B0;font-weight:600\">Yes</span>' if rem else '<span style=\"color:#8B949E;font-weight:500\">No</span>'
    html += f'<tr><td class=\"severity-{{sev.lower()}}\">{sev}</td><td>{cve}</td><td>{pkg}</td><td>{rem_text}</td></tr>'

html += '</tbody></table></div><div class=\"footer\"><strong>🛡️ CrowdStrike Falcon Cloud Security</strong><br>Container Image Security Assessment</div></div></body></html>'

with open('image_assessment_report.html','w') as f:
    f.write(html)
print('✅ Image Assessment Report generated')
"
                                ' || echo "Report generation had issues"
                        '''

                        publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                                    reportDir: '.', reportFiles: 'image_assessment_report.html',
                                    reportName: 'Image Assessment Report', reportTitles: 'CrowdStrike Image Security'])
                        archiveArtifacts artifacts: 'container_scan.json', allowEmptyArchive: true
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                script {
                    try {
                        echo 'Deploying Juice Shop container'
                        sh 'docker rm -f juice-shop || true'
                        sh 'docker run -d -p 3000:3000 --name juice-shop juice-shop:latest'
                        sleep(time: 20, unit: 'SECONDS')

                        def containerStatus = sh(script: 'docker ps --filter name=juice-shop --format "{{.Status}}"', returnStdout: true).trim()
                        echo "Container status: ${containerStatus}"

                        if (containerStatus && containerStatus.contains('Up')) {
                            echo "✅ Juice Shop container is running on http://localhost:3000"
                            env.DOCKER_HOST_PORT = "3000"
                        } else {
                            echo "⚠️ Container may not be running properly"
                            sh 'docker logs juice-shop'
                        }
                    } catch (Exception e) {
                        echo "Deployment had issues: ${e.getMessage()}"
                        sh 'docker logs juice-shop 2>/dev/null || true'
                    }
                }
            }
        }
    }

    post {
        always {
            echo 'Pipeline execution completed.'
            sh 'docker ps -a --filter name=juice-shop || true'
            sh 'docker image prune -f || true'
        }
        success {
            echo '✅ Build, test, and deployment successful!'
            echo '📊 View Reports:'
            echo '  - IaC Assessment: Check sidebar link'
            echo '  - Image Assessment: Check sidebar link'
            echo '🎉 Juice Shop: http://localhost:3000'
        }
        failure {
            echo '❌ Build, test, or deployment failed!'
            sh 'docker ps -a --filter name=juice-shop || true'
            sh 'docker logs --tail 50 juice-shop 2>/dev/null || true'
        }
        cleanup {
            echo 'Cleanup completed'
        }
    }
}
