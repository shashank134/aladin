# ReconJsHunter

## Overview
ReconHunter is a professional-grade OSINT and JavaScript intelligence tool designed for authorized bug bounty security testing. It uses a **modular 3-phase architecture** that separates reconnaissance, JS filtering, and JS analysis for maximum accuracy and flexibility.

## Architecture (3-Phase Pipeline)
```
Phase 1: RECON       → Collect URLs only (no JS analysis)
Phase 2: FILTER-JS   → Extract and categorize JS URLs
Phase 3: ANALYZE-JS  → Deep static analysis with confidence scoring
```

Each phase is independently runnable and persists data between phases.

## How to Run
The web application starts automatically on port 5000. Access the Webview panel to use it.

**CLI Workflow (Recommended):**
```bash
# Phase 1: Collect URLs
cd ReconJsHunter && python cli.py recon example.com -o results

# Phase 2: Extract JS URLs
cd ReconJsHunter && python cli.py filter-js example.com -o results

# Phase 3: Analyze JS files
cd ReconJsHunter && python cli.py analyze-js example.com -o results

# Or run all phases at once:
cd ReconJsHunter && python cli.py pipeline example.com -o results
```

## Project Structure
```
ReconJsHunter/
├── app.py                 # Flask web server (port 5000)
├── cli.py                 # Modular CLI with 3-phase support
├── config.yaml            # Configuration file
├── src/
│   ├── core/
│   │   ├── config.py      # Configuration management
│   │   ├── logger.py      # Colored logging system
│   │   ├── normalizer.py  # URL/domain normalization
│   │   ├── rate_limiter.py # Async rate limiting
│   │   └── scan_cache.py  # Scan caching for resume
│   ├── collectors/        # 8 data source collectors
│   │   ├── base.py, wayback.py, urlscan.py, alienvault.py
│   │   ├── commoncrawl.py, live_discovery.py, search_engines.py
│   │   └── recursive_expander.py
│   ├── models/            # Data models (NEW)
│   │   └── __init__.py    # ReconResult, JsFilterResult, JsAnalysisResult
│   ├── services/          # Shared services (NEW)
│   │   └── datastore.py   # Persistent JSON data storage
│   ├── pipelines/         # 3-phase pipeline runners (NEW)
│   │   ├── recon/runner.py      # Phase 1: URL collection
│   │   ├── js_filter/runner.py  # Phase 2: JS URL filtering
│   │   └── js_analysis/runner.py # Phase 3: Deep JS analysis
│   ├── analyzers/         # Empty (consolidated to pipelines)
│   ├── output/
│   │   ├── json_exporter.py
│   │   └── html_report.py
│   └── recon_engine.py    # Legacy orchestrator
└── recon_output/          # Persistent data storage
    └── <target>/
        ├── recon.json     # Phase 1 output
        ├── js_urls.json   # Phase 2 output
        └── js_findings.json # Phase 3 output
```

## Technology Stack
- **Language**: Python 3.11
- **Web Framework**: Flask
- **Async HTTP**: aiohttp
- **Domain Parsing**: tldextract
- **Configuration**: PyYAML

## Data Sources (8 Collectors)
1. Wayback Machine, 2. Common Crawl, 3. URLScan.io, 4. AlienVault OTX
5. Live Discovery (crawls 20 pages), 6. Google, 7. Bing, 8. DuckDuckGo

## JS Analysis Features (Phase 3)
- **20 Detection Categories**: Credentials, Tokens/Secrets, API Keys, UUIDs, Internal References, Internal Paths, Cloud Data, Sensitive Config, Database, Auth/Session, Network/Infra, Frontend Framework, Debug Artifacts, Business Logic, Privacy Data, File Storage, Security Weakness, Protocol/Comm, Bug Bounty Signals
- **Confidence Scoring**: LOW, MEDIUM, HIGH based on regex + entropy + context
- **150+ Secret Patterns**: AWS, GCP, Azure, Firebase, Stripe, OpenAI, GitHub, Kubernetes, OAuth, CSRF, SSO, WebSocket, gRPC, etc.
- **Context Extraction**: 3 lines before/after each finding with line numbers
- **Entropy Analysis**: Shannon entropy calculation for secret detection

## CLI Commands
```bash
# Modular Commands
python cli.py recon <target>       # Phase 1: Collect URLs
python cli.py filter-js <target>   # Phase 2: Extract JS URLs
python cli.py analyze-js <target>  # Phase 3: Analyze JS files
python cli.py pipeline <target>    # Run all 3 phases
python cli.py status               # Show scan status

# Legacy Commands
python cli.py scan <target>        # Original combined scan
python cli.py batch <file>         # Batch scan from file
python cli.py sources              # List OSINT sources
```

## Web Interface Features
- **3-Phase Workflow UI**: Run each phase independently or use "Run Full Pipeline"
- **Real-time Status**: Visual indicators showing phase progress (Not started, Running, Completed)
- **Results Display**: View URLs by domain, internal/external JS, and findings with confidence badges
- **API Endpoints**: `/api/recon`, `/api/filter-js`, `/api/analyze-js`, `/api/pipeline`, `/api/status`

## HTML Report Features
- **Sidebar Navigation**: Clickable sections for Overview, URLs, JavaScript, Findings
- **Global Search**: Filter all content across the report
- **Stats Dashboard**: Total URLs, Subdomains, JS files, Findings breakdown by confidence
- **Findings Display**: Category badges, confidence levels (HIGH/MEDIUM/LOW), masked values with reveal toggle, context with line numbers, entropy scores

## Recent Changes (Dec 22, 2025)
- **REFACTOR**: Consolidated JS analyzers - removed legacy `src/analyzers/js_analyzer.py`, all code now uses `JsAnalysisRunner` from pipelines
- **FIX**: Resolved 0.0KB file error - JS download now properly handles large compressed files (5MB+)
- **FIX**: Restored SSL/TLS verification for secure HTTPS connections
- **NEW**: Added Brotli decompression support for CDN-served JavaScript files
- **NEW**: Enhanced UI with smooth animations (fadeIn, slideIn, glow effects)
- **NEW**: Gradient backgrounds and hover effects for category sections
- **NEW**: Collapsible category sections with expand/collapse functionality
- **NEW**: Category icons, color coding, and HIGH/MEDIUM count badges per category
- **NEW**: Added 10+ new pattern categories from bug bounty intelligence list
- **NEW**: Auth/Session patterns (OAuth, CSRF, SSO, LDAP, JWT secrets)
- **NEW**: Network/Infrastructure patterns (Kubernetes, Docker, microservices, gRPC)
- **NEW**: Security Weakness patterns (CSP, CORS, localStorage tokens, XSS)
- **NEW**: Bug Bounty Signals patterns (privilege escalation, IDOR, auth bypass)
- **NEW**: Debug Artifacts, Business Logic, Privacy Data, File Storage, Protocol patterns
- **FIX**: JS analyzer now scans RAW content instead of beautified (finds more secrets)
- **FIX**: UI shows ALL JS files with "Load More" pagination (no 50-item limit)
- **NEW**: Relaxed patterns for URLs, emails, API paths, config objects, env references
- **NEW**: Manual "Analyze Single JavaScript URL" input field for direct URL analysis

## Changes (Dec 21, 2025)
- **MAJOR**: Refactored to modular 3-phase architecture
- Added ReconRunner, JsFilterRunner, JsAnalysisRunner pipelines
- Created DataStore service for persistent JSON storage
- Added data models: ReconResult, JsFilterResult, JsAnalysisResult, Finding
- Enhanced JS analyzer with 80+ patterns and confidence scoring
- Live discovery now crawls up to 20 internal pages
- CLI supports new modular commands (recon, filter-js, analyze-js, pipeline)
- Professional HTML report with sidebar navigation, search, and findings display
- Flask web interface with 3-phase workflow UI and API endpoints
