"""
ReconHunter Web Interface
Flask-based web UI for viewing and running reconnaissance scans with live results.
"""

import os
import json
import asyncio
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_from_directory, redirect, url_for

from src.core.config import get_default_config
from src.core.normalizer import URLNormalizer
from src.core.logger import set_silent
from src.recon_engine import ReconEngine

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'reconhunter-dev-key')

OUTPUT_DIR = 'recon_output'
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconHunter - Bug Bounty Reconnaissance</title>
    <style>
        :root {
            --bg-primary: #0a0e14;
            --bg-secondary: #131820;
            --bg-tertiary: #1a2028;
            --bg-card: #161d26;
            --text-primary: #e4e8ed;
            --text-secondary: #7a8694;
            --accent-blue: #3b82f6;
            --accent-cyan: #22d3ee;
            --accent-green: #22c55e;
            --accent-yellow: #eab308;
            --accent-red: #ef4444;
            --accent-purple: #a855f7;
            --accent-orange: #f97316;
            --border-color: #2a3441;
            --gradient-1: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            --gradient-2: linear-gradient(135deg, #22d3ee 0%, #3b82f6 100%);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: var(--bg-secondary);
            padding: 30px 20px;
            text-align: center;
            border-bottom: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--gradient-1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: var(--gradient-2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .header p {
            color: var(--text-secondary);
            font-size: 1rem;
            font-weight: 400;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px 20px;
        }
        
        .scan-form {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.3);
        }
        
        .form-group {
            margin-bottom: 24px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 10px;
            color: var(--text-primary);
            font-weight: 600;
            font-size: 0.95rem;
        }
        
        .form-group input[type="text"] {
            width: 100%;
            padding: 16px 20px;
            background: var(--bg-tertiary);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.2s;
        }
        
        .form-group input[type="text"]:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.15);
        }
        
        .form-group input[type="text"]::placeholder {
            color: var(--text-secondary);
        }
        
        .options-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }
        
        .option-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .option-item:hover {
            border-color: var(--accent-blue);
            background: rgba(59, 130, 246, 0.1);
        }
        
        .option-item input[type="checkbox"] {
            width: 20px;
            height: 20px;
            accent-color: var(--accent-blue);
            cursor: pointer;
        }
        
        .option-item label {
            cursor: pointer;
            font-weight: 500;
        }
        
        .btn {
            padding: 16px 32px;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }
        
        .btn-primary {
            background: var(--gradient-1);
            color: #fff;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.5);
        }
        
        .btn-primary:disabled {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .status-message {
            padding: 16px 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            display: none;
            font-weight: 500;
        }
        
        .status-message.error {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            display: block;
        }
        
        .status-message.success {
            background: rgba(34, 197, 94, 0.15);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            display: block;
        }
        
        .status-message.loading {
            background: rgba(59, 130, 246, 0.15);
            border: 1px solid var(--accent-blue);
            color: var(--accent-blue);
            display: block;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid var(--accent-blue);
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 0.8s linear infinite;
            margin-right: 12px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Live Results Section */
        .results-section {
            display: none;
            margin-bottom: 30px;
        }
        
        .results-section.active {
            display: block;
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .results-header h2 {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: all 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--accent-blue);
        }
        
        .stat-card .number {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 4px;
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }
        
        .stat-card.blue .number { color: var(--accent-blue); }
        .stat-card.cyan .number { color: var(--accent-cyan); }
        .stat-card.green .number { color: var(--accent-green); }
        .stat-card.yellow .number { color: var(--accent-yellow); }
        .stat-card.red .number { color: var(--accent-red); }
        .stat-card.purple .number { color: var(--accent-purple); }
        
        .tabs-container {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            overflow: hidden;
        }
        
        .tabs {
            display: flex;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            overflow-x: auto;
        }
        
        .tab {
            padding: 16px 24px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            border-bottom: 3px solid transparent;
        }
        
        .tab:hover {
            color: var(--text-primary);
            background: rgba(255,255,255,0.05);
        }
        
        .tab.active {
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
            background: rgba(59, 130, 246, 0.1);
        }
        
        .tab-content {
            display: none;
            padding: 24px;
            max-height: 500px;
            overflow-y: auto;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .url-list {
            list-style: none;
        }
        
        .url-list li {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            transition: all 0.2s;
        }
        
        .url-list li:last-child {
            border-bottom: none;
        }
        
        .url-list li:hover {
            background: var(--bg-tertiary);
        }
        
        .url-list a {
            color: var(--accent-cyan);
            text-decoration: none;
        }
        
        .url-list a:hover {
            text-decoration: underline;
        }
        
        .finding-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 12px;
            transition: all 0.2s;
        }
        
        .finding-card:hover {
            border-color: var(--accent-blue);
        }
        
        .finding-card .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            margin-right: 10px;
        }
        
        .finding-card .badge.high { background: var(--accent-red); color: #fff; }
        .finding-card .badge.medium { background: var(--accent-yellow); color: #000; }
        .finding-card .badge.low { background: var(--accent-green); color: #fff; }
        
        .finding-card .type {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        
        .finding-card .value {
            font-family: monospace;
            background: var(--bg-primary);
            padding: 10px 14px;
            border-radius: 8px;
            margin: 10px 0;
            word-break: break-all;
            font-size: 0.85rem;
            border: 1px solid var(--border-color);
        }
        
        .finding-card .source {
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }
        
        /* Previous Reports Section */
        .reports-section {
            margin-top: 30px;
        }
        
        .reports-section h2 {
            margin-bottom: 20px;
            font-size: 1.3rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .reports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
        }
        
        .report-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.2s;
        }
        
        .report-card:hover {
            border-color: var(--accent-blue);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }
        
        .report-card h3 {
            color: var(--accent-cyan);
            margin-bottom: 8px;
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        .report-card .meta {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 16px;
        }
        
        .report-card .actions {
            display: flex;
            gap: 10px;
        }
        
        .report-card .actions a {
            padding: 10px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .report-card .actions a:hover {
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: #fff;
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .header h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ReconHunter</h1>
        <p>Professional Bug Bounty Reconnaissance Tool</p>
    </div>
    
    <div class="container">
        <div class="scan-form">
            <form id="scanForm">
                <div class="form-group">
                    <label for="target">Target Domain or URL</label>
                    <input type="text" id="target" name="target" 
                           placeholder="Enter domain (e.g., example.com) or URL" required>
                </div>
                
                <div class="options-grid">
                    <div class="option-item">
                        <input type="checkbox" id="wayback" name="wayback" checked>
                        <label for="wayback">Wayback Machine</label>
                    </div>
                    <div class="option-item">
                        <input type="checkbox" id="urlscan" name="urlscan" checked>
                        <label for="urlscan">URLScan.io</label>
                    </div>
                    <div class="option-item">
                        <input type="checkbox" id="alienvault" name="alienvault" checked>
                        <label for="alienvault">AlienVault OTX</label>
                    </div>
                    <div class="option-item">
                        <input type="checkbox" id="analyze_js" name="analyze_js" checked>
                        <label for="analyze_js">JavaScript Analysis</label>
                    </div>
                </div>
                
                <div id="statusMessage" class="status-message"></div>
                
                <button type="submit" class="btn btn-primary" id="submitBtn">
                    Start Reconnaissance
                </button>
            </form>
        </div>
        
        <!-- Live Results Section -->
        <div id="resultsSection" class="results-section">
            <div class="results-header">
                <h2>Scan Results</h2>
            </div>
            
            <div class="stats-grid" id="statsGrid">
                <div class="stat-card blue">
                    <div class="number" id="statUrls">0</div>
                    <div class="label">Total URLs</div>
                </div>
                <div class="stat-card cyan">
                    <div class="number" id="statSubdomains">0</div>
                    <div class="label">Subdomains</div>
                </div>
                <div class="stat-card purple">
                    <div class="number" id="statJsFiles">0</div>
                    <div class="label">JS Files</div>
                </div>
                <div class="stat-card green">
                    <div class="number" id="statEndpoints">0</div>
                    <div class="label">Endpoints</div>
                </div>
                <div class="stat-card red">
                    <div class="number" id="statSecrets">0</div>
                    <div class="label">Secrets Found</div>
                </div>
                <div class="stat-card yellow">
                    <div class="number" id="statHighConf">0</div>
                    <div class="label">High Confidence</div>
                </div>
            </div>
            
            <div class="tabs-container">
                <div class="tabs">
                    <button class="tab active" data-tab="urls-tab">URLs</button>
                    <button class="tab" data-tab="subdomains-tab">Subdomains</button>
                    <button class="tab" data-tab="endpoints-tab">Endpoints</button>
                    <button class="tab" data-tab="secrets-tab">Secrets</button>
                    <button class="tab" data-tab="js-tab">JS Files</button>
                </div>
                
                <div id="urls-tab" class="tab-content active">
                    <ul class="url-list" id="urlsList"></ul>
                </div>
                
                <div id="subdomains-tab" class="tab-content">
                    <ul class="url-list" id="subdomainsList"></ul>
                </div>
                
                <div id="endpoints-tab" class="tab-content">
                    <ul class="url-list" id="endpointsList"></ul>
                </div>
                
                <div id="secrets-tab" class="tab-content">
                    <div id="secretsList"></div>
                </div>
                
                <div id="js-tab" class="tab-content">
                    <ul class="url-list" id="jsList"></ul>
                </div>
            </div>
        </div>
        
        <div class="reports-section">
            <h2>Previous Reports</h2>
            <div class="reports-grid" id="reportsGrid">
                {% if reports %}
                    {% for report in reports %}
                    <div class="report-card">
                        <h3>{{ report.domain }}</h3>
                        <div class="meta">{{ report.date }}</div>
                        <div class="actions">
                            <a href="/report/{{ report.folder }}/report.html">View HTML</a>
                            <a href="/report/{{ report.folder }}/full_report.json">View JSON</a>
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                    <div class="empty-state">
                        No reports yet. Start a scan to generate your first report.
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <footer>
        ReconHunter v1.0.0 | For authorized security testing only
    </footer>
    
    <script>
        // Tab functionality
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });
        
        // Form submission
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const target = document.getElementById('target').value;
            const submitBtn = document.getElementById('submitBtn');
            const statusDiv = document.getElementById('statusMessage');
            const resultsSection = document.getElementById('resultsSection');
            
            submitBtn.disabled = true;
            statusDiv.className = 'status-message loading';
            statusDiv.innerHTML = '<span class="loading-spinner"></span>Running reconnaissance... This may take a few minutes.';
            
            // Reset results
            resultsSection.classList.remove('active');
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        target: target,
                        wayback: document.getElementById('wayback').checked,
                        urlscan: document.getElementById('urlscan').checked,
                        alienvault: document.getElementById('alienvault').checked,
                        analyze_js: document.getElementById('analyze_js').checked
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    statusDiv.className = 'status-message success';
                    statusDiv.innerHTML = 'Scan complete! <a href="/report/' + result.report_folder + '/report.html" style="color: inherit; text-decoration: underline;">View Full Report</a>';
                    
                    // Display results on the interface
                    displayResults(result.results);
                    resultsSection.classList.add('active');
                    
                    // Reload after delay to show new report in list
                    setTimeout(() => location.reload(), 5000);
                } else {
                    statusDiv.className = 'status-message error';
                    statusDiv.textContent = 'Error: ' + result.error;
                }
            } catch (error) {
                statusDiv.className = 'status-message error';
                statusDiv.textContent = 'Error: ' + error.message;
            } finally {
                submitBtn.disabled = false;
            }
        });
        
        function displayResults(results) {
            // Update stats
            document.getElementById('statUrls').textContent = results.stats.total_urls || 0;
            document.getElementById('statSubdomains').textContent = results.stats.total_subdomains || 0;
            document.getElementById('statJsFiles').textContent = results.stats.total_js_files || 0;
            document.getElementById('statEndpoints').textContent = results.stats.total_endpoints || 0;
            document.getElementById('statSecrets').textContent = results.stats.total_secrets || 0;
            document.getElementById('statHighConf').textContent = results.stats.high_confidence || 0;
            
            // Populate URLs
            const urlsList = document.getElementById('urlsList');
            urlsList.innerHTML = '';
            (results.urls || []).slice(0, 100).forEach(url => {
                const li = document.createElement('li');
                li.innerHTML = '<a href="' + url + '" target="_blank" rel="noopener">' + url + '</a>';
                urlsList.appendChild(li);
            });
            if (results.urls && results.urls.length === 0) {
                urlsList.innerHTML = '<div class="empty-state">No URLs found</div>';
            }
            
            // Populate Subdomains
            const subdomainsList = document.getElementById('subdomainsList');
            subdomainsList.innerHTML = '';
            (results.subdomains || []).forEach(sub => {
                const li = document.createElement('li');
                li.textContent = sub;
                subdomainsList.appendChild(li);
            });
            if (results.subdomains && results.subdomains.length === 0) {
                subdomainsList.innerHTML = '<div class="empty-state">No subdomains found</div>';
            }
            
            // Populate Endpoints
            const endpointsList = document.getElementById('endpointsList');
            endpointsList.innerHTML = '';
            (results.endpoints || []).slice(0, 100).forEach(ep => {
                const li = document.createElement('li');
                li.textContent = ep;
                endpointsList.appendChild(li);
            });
            if (results.endpoints && results.endpoints.length === 0) {
                endpointsList.innerHTML = '<div class="empty-state">No endpoints found</div>';
            }
            
            // Populate Secrets
            const secretsList = document.getElementById('secretsList');
            secretsList.innerHTML = '';
            (results.secrets || []).forEach(secret => {
                const card = document.createElement('div');
                card.className = 'finding-card';
                card.innerHTML = `
                    <span class="badge ${secret.confidence}">${secret.confidence}</span>
                    <span class="type">${secret.type}</span>
                    <div class="value">${secret.value}</div>
                    <div class="source">Line ${secret.line_number} | Entropy: ${secret.entropy || 'N/A'}</div>
                `;
                secretsList.appendChild(card);
            });
            if (results.secrets && results.secrets.length === 0) {
                secretsList.innerHTML = '<div class="empty-state">No secrets found</div>';
            }
            
            // Populate JS Files
            const jsList = document.getElementById('jsList');
            jsList.innerHTML = '';
            (results.js_files || []).slice(0, 50).forEach(js => {
                const li = document.createElement('li');
                li.innerHTML = '<a href="' + js + '" target="_blank" rel="noopener">' + js + '</a>';
                jsList.appendChild(li);
            });
            if (results.js_files && results.js_files.length === 0) {
                jsList.innerHTML = '<div class="empty-state">No JavaScript files found</div>';
            }
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    reports = get_existing_reports()
    return render_template_string(MAIN_TEMPLATE, reports=reports)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'})
        
        config = get_default_config()
        config.output_dir = OUTPUT_DIR
        config.wayback.enabled = data.get('wayback', True)
        config.urlscan.enabled = data.get('urlscan', True)
        config.alienvault.enabled = data.get('alienvault', True)
        config.js_analysis = data.get('analyze_js', True)
        
        engine = ReconEngine(config)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(engine.run(target, analyze_js=config.js_analysis))
        finally:
            loop.close()
        
        html_path = engine.export_html(target, OUTPUT_DIR)
        json_dir = engine.export_json(target, OUTPUT_DIR)
        
        report_folder = os.path.basename(os.path.dirname(html_path))
        
        # Prepare results for display
        results = engine.get_display_results()
        
        return jsonify({
            'success': True,
            'report_folder': report_folder,
            'html_path': html_path,
            'json_dir': json_dir,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/report/<path:folder>/<path:filename>')
def serve_report(folder, filename):
    report_path = os.path.join(OUTPUT_DIR, folder)
    return send_from_directory(report_path, filename)


def get_existing_reports():
    reports = []
    
    if not os.path.exists(OUTPUT_DIR):
        return reports
    
    for folder in os.listdir(OUTPUT_DIR):
        folder_path = os.path.join(OUTPUT_DIR, folder)
        
        if not os.path.isdir(folder_path):
            continue
        
        html_report = os.path.join(folder_path, 'report.html')
        if not os.path.exists(html_report):
            continue
        
        parts = folder.rsplit('_', 2)
        if len(parts) >= 3:
            domain = parts[0]
            date_str = f"{parts[1]}_{parts[2]}"
            try:
                date = datetime.strptime(date_str, '%Y%m%d_%H%M%S')
                date_formatted = date.strftime('%Y-%m-%d %H:%M:%S')
            except:
                date_formatted = date_str
        else:
            domain = folder
            date_formatted = 'Unknown'
        
        reports.append({
            'folder': folder,
            'domain': domain,
            'date': date_formatted
        })
    
    reports.sort(key=lambda x: x['date'], reverse=True)
    
    return reports


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
