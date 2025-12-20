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
from src.analyzers.js_analyzer import JSAnalysisResult


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
                <div class="section-content">
                    {% if main_domain.urls %}
                    <ul class="url-list">
                        {% for url in main_domain.urls[:200] %}
                        <li><a href="{{ url }}" target="_blank" rel="noopener">{{ url }}</a></li>
                        {% endfor %}
                    </ul>
                    {% if main_domain.urls|length > 200 %}
                    <div class="empty-state">Showing first 200 of {{ main_domain.urls|length }} URLs</div>
                    {% endif %}
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
                            {% for url in data.urls[:20] %}
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
                 js_results: List[JSAnalysisResult],
                 categorized_urls: Dict[str, List[str]],
                 output_dir: str) -> str:
        
        summary = self._generate_summary(collected_data, js_results, categorized_urls)
        subdomains = self._organize_subdomains(collected_data, categorized_urls)
        findings = self._aggregate_findings(js_results)
        
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_folder = f"{domain.replace('.', '_')}_{timestamp}"
        full_output_dir = os.path.join(output_dir, report_folder)
        
        # Ensure endpoints are properly included
        all_endpoints = categorized_urls.get('endpoints', [])
        api_endpoints = [{'endpoint': ep, 'source_file': 'discovered'} for ep in all_endpoints]
        findings['api_endpoints'] = api_endpoints  # Ensure findings has api_endpoints
        
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
                'analysis': [r.to_dict() for r in js_results]
            },
            findings=findings
        )
        
        os.makedirs(full_output_dir, exist_ok=True)
        report_path = os.path.join(full_output_dir, 'report.html')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def _generate_summary(self, collected_data, js_results, categorized_urls):
        total_urls = sum(len(data.urls) for data in collected_data.values())
        total_subdomains = set()
        for data in collected_data.values():
            total_subdomains.update(data.subdomains)
        
        total_secrets = sum(len(r.secrets) for r in js_results)
        high_confidence = sum(1 for r in js_results for s in r.secrets if s.confidence == 'high')
        
        # Count all endpoints found in JS analysis
        js_endpoints = set()
        for result in js_results:
            js_endpoints.update(result.api_endpoints)
        
        # Combine with categorized endpoints
        all_endpoints = set(categorized_urls.get('endpoints', []))
        all_endpoints.update(js_endpoints)
        
        return {
            'total_urls': total_urls,
            'unique_urls': len(categorized_urls.get('all', [])),
            'total_subdomains': len(total_subdomains),
            'total_js_files': len(categorized_urls.get('javascript', [])),
            'js_files_analyzed': len(js_results),
            'total_endpoints': len(all_endpoints),  # Count JS endpoints too
            'total_secrets_found': total_secrets,
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
    
    def _aggregate_findings(self, js_results):
        findings = {
            'secrets': {'high': [], 'medium': [], 'low': []},
            'internal_references': [],
            'sensitive_data': [],
            'api_endpoints': []
        }
        
        for result in js_results:
            for secret in result.secrets:
                finding = secret.to_dict()
                finding['source_file'] = result.url
                findings['secrets'][secret.confidence].append(finding)
            
            for ref in result.internal_refs:
                finding = ref.to_dict()
                finding['source_file'] = result.url
                findings['internal_references'].append(finding)
            
            for endpoint in result.api_endpoints:
                findings['api_endpoints'].append({
                    'endpoint': endpoint,
                    'source_file': result.url
                })
        
        return findings
