"""
HTML report generator.
Creates professional, interactive HTML reports for visualizing reconnaissance results.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Environment, BaseLoader

from src.collectors.base import CollectedData
from src.models import ReconResult, JsFilterResult, JsAnalysisResult, Finding, JsFileAnalysis


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconHunter Report - {{ domain }}</title>
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
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 30px 0;
            margin-bottom: 30px;
            position: relative;
        }
        
        header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-1);
        }
        
        header h1 {
            font-size: 2rem;
            font-weight: 700;
            background: var(--gradient-2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }
        
        header .meta {
            color: var(--text-secondary);
            font-size: 0.95rem;
        }
        
        header .meta strong {
            color: var(--accent-cyan);
        }
        
        .search-container {
            margin-bottom: 25px;
        }
        
        .search-box {
            width: 100%;
            padding: 14px 20px;
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.2s;
        }
        
        .search-box:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.15);
        }
        
        .search-box::placeholder { color: var(--text-secondary); }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }
        
        .stat-card .number {
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 6px;
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .stat-card.blue .number { color: var(--accent-blue); }
        .stat-card.blue::before { background: var(--accent-blue); }
        .stat-card.cyan .number { color: var(--accent-cyan); }
        .stat-card.cyan::before { background: var(--accent-cyan); }
        .stat-card.green .number { color: var(--accent-green); }
        .stat-card.green::before { background: var(--accent-green); }
        .stat-card.yellow .number { color: var(--accent-yellow); }
        .stat-card.yellow::before { background: var(--accent-yellow); }
        .stat-card.red .number { color: var(--accent-red); }
        .stat-card.red::before { background: var(--accent-red); }
        .stat-card.purple .number { color: var(--accent-purple); }
        .stat-card.purple::before { background: var(--accent-purple); }
        
        .tabs {
            display: flex;
            gap: 6px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            background: var(--bg-card);
            padding: 6px;
            border-radius: 14px;
            border: 1px solid var(--border-color);
        }
        
        .tab {
            padding: 12px 24px;
            background: transparent;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.2s;
        }
        
        .tab:hover {
            background: rgba(255,255,255,0.05);
            color: var(--text-primary);
        }
        
        .tab.active {
            background: var(--gradient-1);
            color: #fff;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
        }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-tertiary);
            padding: 18px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .section-header:hover {
            background: rgba(59, 130, 246, 0.1);
        }
        
        .section-header h2 {
            font-size: 1.1rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 600;
        }
        
        .section-header .count {
            background: var(--accent-blue);
            color: #fff;
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
        }
        
        .section-content {
            padding: 20px 24px;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .section-content.collapsed { display: none; }
        
        .url-list { list-style: none; }
        
        .url-list li {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            transition: all 0.2s;
            border-radius: 6px;
            margin-bottom: 4px;
        }
        
        .url-list li:last-child { border-bottom: none; }
        .url-list li:hover { background: var(--bg-tertiary); }
        
        .url-list a {
            color: var(--accent-cyan);
            text-decoration: none;
        }
        
        .url-list a:hover { text-decoration: underline; }
        
        .finding-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 14px;
            transition: all 0.2s;
            border-left: 4px solid transparent;
        }
        
        .finding-card:hover {
            border-color: var(--accent-blue);
            transform: translateX(4px);
        }
        
        .finding-card.high { border-left-color: var(--accent-red); }
        .finding-card.medium { border-left-color: var(--accent-yellow); }
        .finding-card.low { border-left-color: var(--accent-green); }
        
        .finding-card .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            margin-right: 12px;
        }
        
        .finding-card .badge.high { background: var(--accent-red); color: #fff; }
        .finding-card .badge.medium { background: var(--accent-yellow); color: #000; }
        .finding-card .badge.low { background: var(--accent-green); color: #fff; }
        
        .finding-card .type-badge {
            display: inline-block;
            padding: 4px 10px;
            background: var(--bg-primary);
            border-radius: 6px;
            font-size: 0.8rem;
            color: var(--accent-purple);
            font-weight: 600;
        }
        
        .finding-card .value {
            font-family: 'Monaco', 'Menlo', monospace;
            background: var(--bg-primary);
            padding: 12px 16px;
            border-radius: 8px;
            margin: 12px 0;
            word-break: break-all;
            font-size: 0.85rem;
            border: 1px solid var(--border-color);
        }
        
        .finding-card .meta {
            color: var(--text-secondary);
            font-size: 0.8rem;
            display: flex;
            gap: 20px;
        }
        
        .subdomain-block {
            margin-bottom: 20px;
            background: var(--bg-tertiary);
            border-radius: 10px;
            overflow: hidden;
        }
        
        .subdomain-block h3 {
            color: var(--accent-purple);
            font-size: 1rem;
            padding: 14px 18px;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
        }
        
        .subdomain-block .url-list {
            padding: 10px;
        }
        
        .js-file-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 12px;
            overflow: hidden;
        }
        
        .js-file-header {
            padding: 14px 18px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.2s;
        }
        
        .js-file-header:hover { background: rgba(59, 130, 246, 0.1); }
        
        .js-file-url {
            font-family: monospace;
            font-size: 0.85rem;
            word-break: break-all;
            color: var(--accent-cyan);
        }
        
        .js-file-stats {
            display: flex;
            gap: 8px;
        }
        
        .js-file-stats span {
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .js-file-content {
            padding: 18px;
            border-top: 1px solid var(--border-color);
            display: none;
        }
        
        .js-file-content.expanded { display: block; }
        
        .empty-state {
            text-align: center;
            padding: 50px;
            color: var(--text-secondary);
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
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .container { padding: 15px; }
            header h1 { font-size: 1.5rem; }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>ReconHunter Report</h1>
            <div class="meta">
                Target: <strong>{{ domain }}</strong> | 
                Scan Time: {{ scan_time }} | 
                Sources: {{ sources|join(', ') }}
            </div>
        </div>
    </header>
    
    <div class="container">
        <div class="search-container">
            <input type="text" class="search-box" id="globalSearch" placeholder="Search URLs, findings, endpoints...">
        </div>
        
        <div class="stats-grid">
            <div class="stat-card blue" onclick="navigateToTab('main-domain')">
                <div class="number">{{ summary.total_urls }}</div>
                <div class="label">Total URLs</div>
            </div>
            <div class="stat-card cyan" onclick="navigateToTab('subdomains')">
                <div class="number">{{ summary.total_subdomains }}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card purple" onclick="navigateToTab('javascript')">
                <div class="number">{{ summary.total_js_files }}</div>
                <div class="label">JS Files</div>
            </div>
            <div class="stat-card green" onclick="navigateToTab('endpoints')">
                <div class="number">{{ summary.total_endpoints }}</div>
                <div class="label">Endpoints</div>
            </div>
            <div class="stat-card red" onclick="navigateToTab('findings')">
                <div class="number">{{ summary.total_secrets_found }}</div>
                <div class="label">Secrets Found</div>
            </div>
            <div class="stat-card yellow" onclick="navigateToTab('findings')">
                <div class="number">{{ summary.high_confidence_secrets }}</div>
                <div class="label">High Confidence</div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-tab="main-domain">Main Domain</div>
            <div class="tab" data-tab="subdomains">Subdomains</div>
            <div class="tab" data-tab="javascript">JavaScript</div>
            <div class="tab" data-tab="findings">Findings</div>
            <div class="tab" data-tab="endpoints">Endpoints</div>
        </div>
        
        <div id="main-domain" class="tab-content active">
            <div class="section">
                <div class="section-header">
                    <h2>Main Domain URLs <span class="count">{{ main_domain.urls|length }}</span></h2>
                </div>
                <div class="section-content" style="max-height: none;">
                    {% if main_domain.urls %}
                    <ul class="url-list" id="mainUrlList">
                        {% for url in main_domain.urls %}
                        <li><a href="{{ url }}" target="_blank" rel="noopener">{{ url }}</a></li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <div class="empty-state">No main domain URLs found</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="subdomains" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>Discovered Subdomains <span class="count">{{ subdomains|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if subdomains %}
                    {% for subdomain, data in subdomains.items() %}
                    <div class="subdomain-block">
                        <h3>{{ subdomain }} ({{ data.url_count }} URLs)</h3>
                        <ul class="url-list">
                            {% for url in data.urls %}
                            <li><a href="{{ url }}" target="_blank" rel="noopener">{{ url }}</a></li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No subdomains discovered</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="javascript" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>JavaScript Analysis <span class="count">{{ javascript.analysis|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if javascript.analysis %}
                    {% for js in javascript.analysis %}
                    <div class="js-file-card">
                        <div class="js-file-header" onclick="toggleJsFile(this)">
                            <span class="js-file-url">{{ js.url }}</span>
                            <div class="js-file-stats">
                                {% if js.secrets %}
                                <span style="background: var(--accent-red); color: #fff;">{{ js.secrets|length }} secrets</span>
                                {% endif %}
                                {% if js.api_endpoints %}
                                <span style="background: var(--accent-green); color: #fff;">{{ js.api_endpoints|length }} endpoints</span>
                                {% endif %}
                            </div>
                        </div>
                        <div class="js-file-content">
                            {% if js.secrets %}
                            <h4 style="margin-bottom: 12px; color: var(--accent-red);">Secrets Found:</h4>
                            {% for secret in js.secrets %}
                            <div class="finding-card {{ secret.confidence }}">
                                <span class="badge {{ secret.confidence }}">{{ secret.confidence }}</span>
                                <span class="type-badge">{{ secret.type }}</span>
                                <div class="value">{{ secret.value }}</div>
                                <div class="meta">
                                    <span>Line {{ secret.line_number }}</span>
                                    <span>Entropy: {{ secret.entropy }}</span>
                                </div>
                            </div>
                            {% endfor %}
                            {% endif %}
                            
                            {% if js.api_endpoints %}
                            <h4 style="margin: 18px 0 12px; color: var(--accent-green);">API Endpoints:</h4>
                            <ul class="url-list">
                                {% for endpoint in js.api_endpoints[:20] %}
                                <li>{{ endpoint }}</li>
                                {% endfor %}
                            </ul>
                            {% endif %}
                            
                            {% if js.internal_refs %}
                            <h4 style="margin: 18px 0 12px; color: var(--accent-yellow);">Internal References:</h4>
                            {% for ref in js.internal_refs[:10] %}
                            <div class="finding-card medium">
                                <span class="type-badge">{{ ref.type }}</span>
                                <div class="value">{{ ref.value }}</div>
                            </div>
                            {% endfor %}
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No JavaScript files analyzed</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="findings" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>High Confidence Secrets <span class="count">{{ findings.secrets.high|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.secrets.high %}
                    {% for finding in findings.secrets.high %}
                    <div class="finding-card high">
                        <span class="badge high">HIGH</span>
                        <span class="type-badge">{{ finding.type }}</span>
                        <div class="value">{{ finding.value }}</div>
                        <div class="meta">
                            <span>Source: {{ finding.source_file }}</span>
                            <span>Entropy: {{ finding.entropy }}</span>
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No high confidence secrets found</div>
                    {% endif %}
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>Medium Confidence Secrets <span class="count">{{ findings.secrets.medium|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.secrets.medium %}
                    {% for finding in findings.secrets.medium %}
                    <div class="finding-card medium">
                        <span class="badge medium">MEDIUM</span>
                        <span class="type-badge">{{ finding.type }}</span>
                        <div class="value">{{ finding.value }}</div>
                        <div class="meta">
                            <span>Source: {{ finding.source_file }}</span>
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No medium confidence secrets found</div>
                    {% endif %}
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>Internal References <span class="count">{{ findings.internal_references|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.internal_references %}
                    {% for ref in findings.internal_references[:50] %}
                    <div class="finding-card medium">
                        <span class="type-badge">{{ ref.type }}</span>
                        <div class="value">{{ ref.value }}</div>
                        <div class="meta">
                            <span>Source: {{ ref.source_file }}</span>
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No internal references found</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div id="endpoints" class="tab-content">
            <div class="section">
                <div class="section-header">
                    <h2>Discovered API Endpoints <span class="count">{{ findings.api_endpoints|length }}</span></h2>
                </div>
                <div class="section-content">
                    {% if findings.api_endpoints %}
                    <ul class="url-list">
                        {% for ep in findings.api_endpoints[:200] %}
                        <li>
                            <span style="color: var(--accent-green); font-weight: 600;">{{ ep.endpoint }}</span>
                            <br><small style="color: var(--text-secondary);">from: {{ ep.source_file }}</small>
                        </li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <div class="empty-state">No API endpoints discovered</div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        Generated by ReconHunter v1.0.0 | For authorized security testing only
    </footer>
    
    <script>
        function navigateToTab(tabId) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            const selectedTab = document.querySelector(`[data-tab="${tabId}"]`);
            const selectedContent = document.getElementById(tabId);
            
            if (selectedTab) selectedTab.classList.add('active');
            if (selectedContent) selectedContent.classList.add('active');
        }
        
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                navigateToTab(tab.dataset.tab);
            });
        });
        
        document.querySelectorAll('.section-header').forEach(header => {
            header.addEventListener('click', () => {
                const content = header.nextElementSibling;
                content.classList.toggle('collapsed');
            });
        });
        
        function toggleJsFile(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('expanded');
        }
        
        document.getElementById('globalSearch').addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            
            document.querySelectorAll('.url-list li, .finding-card, .js-file-card, .subdomain-block').forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? '' : 'none';
            });
        });
    </script>
</body>
</html>
'''


class HTMLReportGenerator:
    
    def __init__(self):
        self.env = Environment(loader=BaseLoader())
        self.template = self.env.from_string(HTML_TEMPLATE)
    
    def generate(self, domain: str, collected_data: Dict[str, CollectedData],
                 js_result: JsAnalysisResult,
                 categorized_urls: Dict[str, List[str]],
                 output_dir: str) -> str:
        
        summary = self._generate_summary(collected_data, js_result, categorized_urls)
        subdomains = self._organize_subdomains(collected_data, categorized_urls)
        findings = self._aggregate_findings(js_result)
        
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_folder = f"{domain.replace('.', '_')}_{timestamp}"
        full_output_dir = os.path.join(output_dir, report_folder)
        
        all_endpoints = categorized_urls.get('endpoints', [])
        api_endpoints = [{'endpoint': ep, 'source_file': 'discovered'} for ep in all_endpoints]
        findings['api_endpoints'].extend(api_endpoints)
        
        js_analysis_data = []
        if js_result:
            for file_analysis in js_result.files_analyzed:
                js_analysis_data.append(file_analysis.to_dict())
        
        html_content = self.template.render(
            domain=domain,
            scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            sources=[name for name in collected_data.keys()],
            summary=summary,
            main_domain={
                'urls': categorized_urls.get('main_domain', []),
                'endpoints': categorized_urls.get('endpoints', [])
            },
            subdomains=subdomains,
            javascript={
                'files': categorized_urls.get('javascript', []),
                'analysis': js_analysis_data
            },
            findings=findings
        )
        
        os.makedirs(full_output_dir, exist_ok=True)
        report_path = os.path.join(full_output_dir, 'report.html')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def _generate_summary(self, collected_data, js_result: JsAnalysisResult, categorized_urls):
        total_urls = sum(len(data.urls) for data in collected_data.values())
        total_subdomains = set()
        for data in collected_data.values():
            total_subdomains.update(data.subdomains)
        
        total_findings = 0
        high_confidence = 0
        js_endpoints = set()
        files_analyzed = 0
        
        if js_result:
            total_findings = js_result.total_findings
            high_confidence = js_result.findings_by_confidence.get('high', 0)
            files_analyzed = len(js_result.files_analyzed)
            for file_analysis in js_result.files_analyzed:
                for finding in file_analysis.findings:
                    if finding.category == 'api_endpoint':
                        js_endpoints.add(finding.value)
        
        all_endpoints = set(categorized_urls.get('endpoints', []))
        all_endpoints.update(js_endpoints)
        
        return {
            'total_urls': total_urls,
            'unique_urls': len(categorized_urls.get('all', [])),
            'total_subdomains': len(total_subdomains),
            'total_js_files': len(categorized_urls.get('javascript', [])),
            'js_files_analyzed': files_analyzed,
            'total_endpoints': len(all_endpoints),
            'total_secrets_found': total_findings,
            'high_confidence_secrets': high_confidence,
            'sources_used': list(collected_data.keys())
        }
    
    def _organize_subdomains(self, collected_data, categorized_urls):
        subdomains = {}
        all_subdomains = set()
        
        for data in collected_data.values():
            all_subdomains.update(data.subdomains)
        
        subdomain_urls = categorized_urls.get('subdomain_urls', {})
        
        for subdomain in sorted(all_subdomains):
            subdomains[subdomain] = {
                'urls': subdomain_urls.get(subdomain, []),
                'url_count': len(subdomain_urls.get(subdomain, []))
            }
        
        return subdomains
    
    def _aggregate_findings(self, js_result: JsAnalysisResult):
        findings = {
            'secrets': {'high': [], 'medium': [], 'low': []},
            'internal_references': [],
            'sensitive_data': [],
            'api_endpoints': []
        }
        
        if not js_result:
            return findings
        
        for file_analysis in js_result.files_analyzed:
            for finding in file_analysis.findings:
                finding_dict = finding.to_dict()
                finding_dict['source_file'] = file_analysis.url
                
                confidence = finding.confidence.value if hasattr(finding.confidence, 'value') else str(finding.confidence)
                
                if finding.category in ('api_key', 'secret', 'credential', 'token'):
                    if confidence in findings['secrets']:
                        findings['secrets'][confidence].append(finding_dict)
                    else:
                        findings['secrets']['medium'].append(finding_dict)
                elif finding.category == 'internal_reference':
                    findings['internal_references'].append(finding_dict)
                elif finding.category == 'api_endpoint':
                    findings['api_endpoints'].append({
                        'endpoint': finding.value,
                        'source_file': file_analysis.url
                    })
                elif finding.category in ('sensitive_data', 'pii'):
                    findings['sensitive_data'].append(finding_dict)
                else:
                    if confidence in findings['secrets']:
                        findings['secrets'][confidence].append(finding_dict)
                    else:
                        findings['secrets']['medium'].append(finding_dict)
        
        return findings


MODULAR_HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconJsHunter Report - {{ target }}</title>
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
            --sidebar-width: 260px;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            display: flex;
            min-height: 100vh;
        }
        
        .sidebar {
            width: var(--sidebar-width);
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            overflow-y: auto;
            z-index: 100;
            transition: transform 0.3s ease;
        }
        
        .sidebar-header {
            padding: 24px 20px;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-tertiary);
        }
        
        .sidebar-header h1 {
            font-size: 1.2rem;
            font-weight: 700;
            background: var(--gradient-2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .sidebar-header .target {
            font-size: 0.85rem;
            color: var(--accent-cyan);
            margin-top: 6px;
            word-break: break-all;
        }
        
        .nav-section {
            padding: 16px 0;
        }
        
        .nav-section-title {
            padding: 8px 20px;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-secondary);
            font-weight: 600;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 20px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            transition: all 0.2s;
            cursor: pointer;
            border-left: 3px solid transparent;
        }
        
        .nav-item:hover {
            background: rgba(59, 130, 246, 0.1);
            color: var(--text-primary);
        }
        
        .nav-item.active {
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent-blue);
            border-left-color: var(--accent-blue);
        }
        
        .nav-item .count {
            margin-left: auto;
            background: var(--bg-primary);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .nav-icon {
            width: 18px;
            height: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .main-content {
            margin-left: var(--sidebar-width);
            flex: 1;
            padding: 30px;
            min-height: 100vh;
        }
        
        .search-container {
            margin-bottom: 25px;
            position: sticky;
            top: 0;
            z-index: 50;
            background: var(--bg-primary);
            padding: 10px 0;
        }
        
        .search-box {
            width: 100%;
            padding: 14px 20px 14px 50px;
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.2s;
        }
        
        .search-box:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.15);
        }
        
        .search-box::placeholder { color: var(--text-secondary); }
        
        .search-wrapper {
            position: relative;
        }
        
        .search-icon {
            position: absolute;
            left: 18px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-secondary);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }
        
        .stat-card .number {
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 4px;
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .stat-card.blue .number { color: var(--accent-blue); }
        .stat-card.blue::before { background: var(--accent-blue); }
        .stat-card.cyan .number { color: var(--accent-cyan); }
        .stat-card.cyan::before { background: var(--accent-cyan); }
        .stat-card.green .number { color: var(--accent-green); }
        .stat-card.green::before { background: var(--accent-green); }
        .stat-card.yellow .number { color: var(--accent-yellow); }
        .stat-card.yellow::before { background: var(--accent-yellow); }
        .stat-card.red .number { color: var(--accent-red); }
        .stat-card.red::before { background: var(--accent-red); }
        .stat-card.purple .number { color: var(--accent-purple); }
        .stat-card.purple::before { background: var(--accent-purple); }
        .stat-card.orange .number { color: var(--accent-orange); }
        .stat-card.orange::before { background: var(--accent-orange); }
        
        .section {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        .section.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .section-title .icon {
            width: 40px;
            height: 40px;
            background: var(--gradient-1);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background: var(--bg-tertiary);
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .card-header h3 {
            font-size: 1rem;
            font-weight: 600;
        }
        
        .card-header .badge {
            background: var(--accent-blue);
            color: #fff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
        }
        
        .card-content {
            padding: 20px;
            max-height: 500px;
            overflow-y: auto;
        }
        
        .url-list { list-style: none; }
        
        .url-list li {
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 0.8rem;
            word-break: break-all;
            transition: all 0.2s;
            border-radius: 6px;
            margin-bottom: 4px;
        }
        
        .url-list li:last-child { border-bottom: none; }
        .url-list li:hover { background: var(--bg-tertiary); }
        
        .url-list a {
            color: var(--accent-cyan);
            text-decoration: none;
        }
        
        .url-list a:hover { text-decoration: underline; }
        
        .domain-block {
            margin-bottom: 16px;
            background: var(--bg-tertiary);
            border-radius: 10px;
            overflow: hidden;
        }
        
        .domain-block-header {
            padding: 14px 18px;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .domain-block-header:hover {
            background: rgba(59, 130, 246, 0.1);
        }
        
        .domain-block-header h4 {
            color: var(--accent-purple);
            font-size: 0.95rem;
            font-weight: 600;
        }
        
        .domain-block-content {
            padding: 10px;
            display: none;
        }
        
        .domain-block-content.expanded {
            display: block;
        }
        
        .filter-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .filter-tab {
            padding: 8px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            cursor: pointer;
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .filter-tab:hover {
            border-color: var(--accent-blue);
            color: var(--text-primary);
        }
        
        .filter-tab.active {
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: #fff;
        }
        
        .finding-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 14px;
            transition: all 0.2s;
            border-left: 4px solid transparent;
        }
        
        .finding-card:hover {
            border-color: var(--accent-blue);
        }
        
        .finding-card.high { border-left-color: var(--accent-red); }
        .finding-card.medium { border-left-color: var(--accent-yellow); }
        .finding-card.low { border-left-color: var(--accent-green); }
        
        .finding-header {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 12px;
        }
        
        .confidence-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .confidence-badge.high { background: var(--accent-red); color: #fff; }
        .confidence-badge.medium { background: var(--accent-yellow); color: #000; }
        .confidence-badge.low { background: var(--accent-green); color: #fff; }
        
        .category-badge {
            display: inline-block;
            padding: 4px 10px;
            background: var(--bg-primary);
            border-radius: 6px;
            font-size: 0.75rem;
            color: var(--accent-purple);
            font-weight: 600;
        }
        
        .type-badge {
            display: inline-block;
            padding: 4px 10px;
            background: var(--bg-card);
            border-radius: 6px;
            font-size: 0.75rem;
            color: var(--accent-cyan);
            font-weight: 600;
        }
        
        .value-container {
            position: relative;
            margin: 12px 0;
        }
        
        .value-display {
            font-family: 'Monaco', 'Menlo', monospace;
            background: var(--bg-primary);
            padding: 12px 16px;
            border-radius: 8px;
            word-break: break-all;
            font-size: 0.85rem;
            border: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }
        
        .value-text {
            flex: 1;
            overflow: hidden;
        }
        
        .reveal-btn {
            background: var(--accent-blue);
            color: #fff;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 600;
            transition: all 0.2s;
            white-space: nowrap;
        }
        
        .reveal-btn:hover {
            background: #2563eb;
        }
        
        .context-block {
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 14px;
            margin-top: 12px;
            border: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.8rem;
            overflow-x: auto;
        }
        
        .context-line {
            display: flex;
            padding: 2px 0;
        }
        
        .context-line.highlight {
            background: rgba(239, 68, 68, 0.2);
            border-radius: 4px;
            padding: 2px 6px;
            margin: 0 -6px;
        }
        
        .line-number {
            color: var(--text-secondary);
            min-width: 50px;
            text-align: right;
            padding-right: 12px;
            user-select: none;
        }
        
        .line-content {
            flex: 1;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .finding-meta {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            color: var(--text-secondary);
            font-size: 0.8rem;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
        }
        
        .finding-meta span {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .js-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 10px;
            overflow: hidden;
        }
        
        .js-card-header {
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .js-card-header:hover {
            background: rgba(59, 130, 246, 0.1);
        }
        
        .js-url {
            font-family: monospace;
            font-size: 0.8rem;
            word-break: break-all;
            color: var(--accent-cyan);
            flex: 1;
        }
        
        .js-badge {
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 600;
            margin-left: 10px;
        }
        
        .js-badge.internal {
            background: var(--accent-green);
            color: #fff;
        }
        
        .js-badge.external {
            background: var(--accent-orange);
            color: #fff;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 20px;
        }
        
        .chart-title {
            font-size: 0.9rem;
            font-weight: 600;
            margin-bottom: 16px;
            color: var(--text-secondary);
        }
        
        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .bar-item {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .bar-label {
            width: 80px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        
        .bar-track {
            flex: 1;
            height: 24px;
            background: var(--bg-primary);
            border-radius: 6px;
            overflow: hidden;
            position: relative;
        }
        
        .bar-fill {
            height: 100%;
            border-radius: 6px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 8px;
            font-size: 0.75rem;
            font-weight: 600;
            color: #fff;
        }
        
        .bar-fill.high { background: var(--accent-red); }
        .bar-fill.medium { background: var(--accent-yellow); color: #000; }
        .bar-fill.low { background: var(--accent-green); }
        
        .empty-state {
            text-align: center;
            padding: 50px;
            color: var(--text-secondary);
        }
        
        .empty-state-icon {
            font-size: 3rem;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.open {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <aside class="sidebar">
        <div class="sidebar-header">
            <h1>ReconJsHunter</h1>
            <div class="target">{{ target }}</div>
        </div>
        
        <nav class="nav-section">
            <div class="nav-section-title">Navigation</div>
            <div class="nav-item active" data-section="overview">
                <span class="nav-icon">📊</span>
                Overview Dashboard
            </div>
            <div class="nav-item" data-section="urls">
                <span class="nav-icon">🔗</span>
                Discovered URLs
                <span class="count">{{ stats.total_urls }}</span>
            </div>
            <div class="nav-item" data-section="javascript">
                <span class="nav-icon">📜</span>
                JavaScript Files
                <span class="count">{{ stats.total_js }}</span>
            </div>
            <div class="nav-item" data-section="findings">
                <span class="nav-icon">🔍</span>
                Findings
                <span class="count">{{ stats.total_findings }}</span>
            </div>
        </nav>
        
        <nav class="nav-section">
            <div class="nav-section-title">Quick Stats</div>
            <div class="nav-item" style="cursor: default;">
                <span class="nav-icon">🔴</span>
                High Confidence
                <span class="count" style="background: var(--accent-red);">{{ stats.high_count }}</span>
            </div>
            <div class="nav-item" style="cursor: default;">
                <span class="nav-icon">🟡</span>
                Medium Confidence
                <span class="count" style="background: var(--accent-yellow); color: #000;">{{ stats.medium_count }}</span>
            </div>
            <div class="nav-item" style="cursor: default;">
                <span class="nav-icon">🟢</span>
                Low Confidence
                <span class="count" style="background: var(--accent-green);">{{ stats.low_count }}</span>
            </div>
        </nav>
    </aside>
    
    <main class="main-content">
        <div class="search-container">
            <div class="search-wrapper">
                <span class="search-icon">🔍</span>
                <input type="text" class="search-box" id="globalSearch" placeholder="Search URLs, findings, JavaScript files...">
            </div>
        </div>
        
        <section id="overview" class="section active">
            <h2 class="section-title">
                <span class="icon">📊</span>
                Overview Dashboard
            </h2>
            
            <div class="stats-grid">
                <div class="stat-card blue" onclick="navigateToSection('urls')">
                    <div class="number">{{ stats.total_urls }}</div>
                    <div class="label">Total URLs</div>
                </div>
                <div class="stat-card cyan" onclick="navigateToSection('urls')">
                    <div class="number">{{ stats.total_subdomains }}</div>
                    <div class="label">Subdomains</div>
                </div>
                <div class="stat-card green" onclick="navigateToSection('javascript')">
                    <div class="number">{{ stats.internal_js }}</div>
                    <div class="label">Internal JS</div>
                </div>
                <div class="stat-card orange" onclick="navigateToSection('javascript')">
                    <div class="number">{{ stats.external_js }}</div>
                    <div class="label">External JS</div>
                </div>
                <div class="stat-card purple" onclick="navigateToSection('findings')">
                    <div class="number">{{ stats.total_findings }}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-card red" onclick="navigateToSection('findings')">
                    <div class="number">{{ stats.high_count }}</div>
                    <div class="label">High Confidence</div>
                </div>
                <div class="stat-card yellow" onclick="navigateToSection('findings')">
                    <div class="number">{{ stats.medium_count }}</div>
                    <div class="label">Medium Confidence</div>
                </div>
            </div>
            
            <div class="chart-container">
                <div class="chart-card">
                    <div class="chart-title">Confidence Breakdown</div>
                    <div class="bar-chart">
                        <div class="bar-item">
                            <span class="bar-label">High</span>
                            <div class="bar-track">
                                <div class="bar-fill high" style="width: {{ (stats.high_count / stats.total_findings * 100) if stats.total_findings > 0 else 0 }}%;">
                                    {{ stats.high_count }}
                                </div>
                            </div>
                        </div>
                        <div class="bar-item">
                            <span class="bar-label">Medium</span>
                            <div class="bar-track">
                                <div class="bar-fill medium" style="width: {{ (stats.medium_count / stats.total_findings * 100) if stats.total_findings > 0 else 0 }}%;">
                                    {{ stats.medium_count }}
                                </div>
                            </div>
                        </div>
                        <div class="bar-item">
                            <span class="bar-label">Low</span>
                            <div class="bar-track">
                                <div class="bar-fill low" style="width: {{ (stats.low_count / stats.total_findings * 100) if stats.total_findings > 0 else 0 }}%;">
                                    {{ stats.low_count }}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="chart-card">
                    <div class="chart-title">Findings by Category</div>
                    <div class="bar-chart">
                        {% for category, count in categories.items() %}
                        <div class="bar-item">
                            <span class="bar-label" style="width: 120px;">{{ category }}</span>
                            <div class="bar-track">
                                <div class="bar-fill" style="width: {{ (count / stats.total_findings * 100) if stats.total_findings > 0 else 0 }}%; background: var(--accent-purple);">
                                    {{ count }}
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3>Scan Information</h3>
                </div>
                <div class="card-content">
                    <p><strong>Target:</strong> {{ target }}</p>
                    <p><strong>Scan ID:</strong> {{ scan_id }}</p>
                    <p><strong>Scan Time:</strong> {{ scan_time }}</p>
                    <p><strong>Sources Used:</strong> {{ sources|join(', ') }}</p>
                </div>
            </div>
        </section>
        
        <section id="urls" class="section">
            <h2 class="section-title">
                <span class="icon">🔗</span>
                Discovered URLs
            </h2>
            
            {% for domain, urls in urls_by_domain.items() %}
            <div class="domain-block">
                <div class="domain-block-header" onclick="toggleDomainBlock(this)">
                    <h4>{{ domain }}</h4>
                    <span class="badge" style="background: var(--accent-blue); color: #fff; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem;">{{ urls|length }} URLs</span>
                </div>
                <div class="domain-block-content">
                    <ul class="url-list">
                        {% for url_obj in urls %}
                        <li><a href="{{ url_obj.url }}" target="_blank" rel="noopener">{{ url_obj.url }}</a></li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
            {% else %}
            <div class="empty-state">
                <div class="empty-state-icon">🔗</div>
                <p>No URLs discovered</p>
            </div>
            {% endfor %}
        </section>
        
        <section id="javascript" class="section">
            <h2 class="section-title">
                <span class="icon">📜</span>
                JavaScript Files
            </h2>
            
            <div class="card">
                <div class="card-header">
                    <h3>Internal JavaScript</h3>
                    <span class="badge" style="background: var(--accent-green);">{{ internal_js|length }}</span>
                </div>
                <div class="card-content">
                    {% if internal_js %}
                    {% for js in internal_js %}
                    <div class="js-card">
                        <div class="js-card-header">
                            <span class="js-url">{{ js.url }}</span>
                            <span class="js-badge internal">Internal</span>
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No internal JavaScript files found</div>
                    {% endif %}
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3>External JavaScript</h3>
                    <span class="badge" style="background: var(--accent-orange);">{{ external_js|length }}</span>
                </div>
                <div class="card-content">
                    {% if external_js %}
                    {% for js in external_js %}
                    <div class="js-card">
                        <div class="js-card-header">
                            <span class="js-url">{{ js.url }}</span>
                            <span class="js-badge external">External</span>
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">No external JavaScript files found</div>
                    {% endif %}
                </div>
            </div>
        </section>
        
        <section id="findings" class="section">
            <h2 class="section-title">
                <span class="icon">🔍</span>
                Findings
            </h2>
            
            <div class="filter-tabs">
                <div class="filter-tab active" data-filter="all">All</div>
                {% for category in categories.keys() %}
                <div class="filter-tab" data-filter="{{ category }}">{{ category }}</div>
                {% endfor %}
            </div>
            
            <div id="findings-container">
                {% for file_analysis in files_analyzed %}
                {% for finding in file_analysis.findings %}
                <div class="finding-card {{ finding.confidence.value }}" data-category="{{ finding.category }}">
                    <div class="finding-header">
                        <span class="confidence-badge {{ finding.confidence.value }}">{{ finding.confidence.value }}</span>
                        <span class="category-badge">{{ finding.category }}</span>
                        <span class="type-badge">{{ finding.finding_type }}</span>
                    </div>
                    
                    <div class="value-container">
                        <div class="value-display">
                            <span class="value-text" data-masked="true" data-value="{{ finding.value }}">{{ finding.value[:8] }}{{ '*' * (finding.value|length - 8) if finding.value|length > 8 else '' }}</span>
                            <button class="reveal-btn" onclick="toggleReveal(this)">Reveal</button>
                        </div>
                    </div>
                    
                    {% if finding.context %}
                    <div class="context-block">
                        {% set context_lines = finding.context.split('\\n') %}
                        {% for line in context_lines %}
                        <div class="context-line {% if finding.value in line %}highlight{% endif %}">
                            <span class="line-number">{{ (finding.line_number - (context_lines|length // 2) + loop.index0) if finding.line_number else loop.index }}</span>
                            <span class="line-content">{{ line }}</span>
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    <div class="finding-meta">
                        <span>📁 {{ file_analysis.url }}</span>
                        {% if finding.line_number %}
                        <span>📍 Line {{ finding.line_number }}</span>
                        {% endif %}
                        {% if finding.entropy %}
                        <span>📈 Entropy: {{ "%.2f"|format(finding.entropy) }}</span>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                {% else %}
                <div class="empty-state">
                    <div class="empty-state-icon">🔍</div>
                    <p>No findings discovered</p>
                </div>
                {% endfor %}
            </div>
        </section>
    </main>
    
    <script>
        function navigateToSection(sectionId) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            
            const section = document.getElementById(sectionId);
            const navItem = document.querySelector(`[data-section="${sectionId}"]`);
            
            if (section) section.classList.add('active');
            if (navItem) navItem.classList.add('active');
        }
        
        document.querySelectorAll('.nav-item[data-section]').forEach(item => {
            item.addEventListener('click', () => {
                navigateToSection(item.dataset.section);
            });
        });
        
        function toggleDomainBlock(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('expanded');
        }
        
        function toggleReveal(btn) {
            const valueSpan = btn.previousElementSibling;
            const isMasked = valueSpan.dataset.masked === 'true';
            const originalValue = valueSpan.dataset.value;
            
            if (isMasked) {
                valueSpan.textContent = originalValue;
                valueSpan.dataset.masked = 'false';
                btn.textContent = 'Hide';
            } else {
                const masked = originalValue.substring(0, 8) + '*'.repeat(Math.max(0, originalValue.length - 8));
                valueSpan.textContent = masked;
                valueSpan.dataset.masked = 'true';
                btn.textContent = 'Reveal';
            }
        }
        
        document.querySelectorAll('.filter-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                const filter = tab.dataset.filter;
                document.querySelectorAll('.finding-card').forEach(card => {
                    if (filter === 'all' || card.dataset.category === filter) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        });
        
        document.getElementById('globalSearch').addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            
            document.querySelectorAll('.url-list li, .finding-card, .js-card, .domain-block').forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? '' : 'none';
            });
        });
    </script>
</body>
</html>
'''


def generate_modular_html_report(
    target: str,
    recon_result: ReconResult,
    js_filter_result: JsFilterResult,
    js_analysis_result: JsAnalysisResult,
    output_dir: str
) -> str:
    """
    Generate a professional HTML report from the modular 3-phase pipeline data.
    
    Args:
        target: The target domain/URL that was scanned
        recon_result: Results from the reconnaissance phase
        js_filter_result: Results from the JavaScript filtering phase
        js_analysis_result: Results from the JavaScript analysis phase
        output_dir: Directory where the report should be saved
    
    Returns:
        Path to the generated HTML report file
    """
    env = Environment(loader=BaseLoader())
    template = env.from_string(MODULAR_HTML_TEMPLATE)
    
    high_count = js_analysis_result.findings_by_confidence.get('high', 0)
    medium_count = js_analysis_result.findings_by_confidence.get('medium', 0)
    low_count = js_analysis_result.findings_by_confidence.get('low', 0)
    
    stats = {
        'total_urls': recon_result.total_urls,
        'total_subdomains': len(recon_result.urls_by_domain),
        'total_js': js_filter_result.total_js_urls,
        'internal_js': len(js_filter_result.internal_js),
        'external_js': len(js_filter_result.external_js),
        'total_findings': js_analysis_result.total_findings,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count
    }
    
    urls_by_domain = {}
    for domain, discovered_urls in recon_result.urls_by_domain.items():
        urls_by_domain[domain] = discovered_urls
    
    internal_js = [js.to_dict() for js in js_filter_result.internal_js]
    external_js = [js.to_dict() for js in js_filter_result.external_js]
    
    categories = js_analysis_result.findings_by_category.copy()
    
    html_content = template.render(
        target=target,
        scan_id=recon_result.scan_id,
        scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        sources=recon_result.sources_used,
        stats=stats,
        urls_by_domain=urls_by_domain,
        internal_js=internal_js,
        external_js=external_js,
        files_analyzed=js_analysis_result.files_analyzed,
        categories=categories
    )
    
    os.makedirs(output_dir, exist_ok=True)
    
    safe_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"{safe_target}_{timestamp}_modular_report.html"
    report_path = os.path.join(output_dir, report_filename)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path
