"""
Main reconnaissance engine.
Orchestrates all collectors and analyzers with stealth and silent mode support.
"""

import asyncio
from typing import Dict, List, Set
import aiohttp

from src.core.config import Config, get_default_config
from src.core.normalizer import URLNormalizer, normalize_input
from src.core.logger import logger, set_silent
from src.collectors.base import CollectedData
from src.collectors.wayback import WaybackCollector
from src.collectors.urlscan import URLScanCollector
from src.collectors.alienvault import AlienVaultCollector
from src.collectors.commoncrawl import CommonCrawlCollector
from src.collectors.live_discovery import LiveDiscoveryCollector
from src.analyzers.js_analyzer import JSAnalyzer, JSAnalysisResult
from src.output.json_exporter import JSONExporter
from src.output.html_report import HTMLReportGenerator


class ReconEngine:
    
    def __init__(self, config: Config = None, silent_mode: bool = False):
        self.config = config or get_default_config()
        self.normalizer = URLNormalizer()
        self.silent_mode = silent_mode
        
        if silent_mode:
            set_silent(True)
        
        self.collectors = []
        self.collected_data: Dict[str, CollectedData] = {}
        self.js_results: List[JSAnalysisResult] = []
        self.categorized_urls: Dict[str, List[str]] = {}
    
    async def run(self, target: str, analyze_js: bool = True) -> Dict:
        domain = self.normalizer.normalize_domain(target)
        
        if not self.silent_mode:
            logger.info(f"Starting reconnaissance for: {domain}")
        
        await self._collect_osint(domain)
        
        self._categorize_urls(domain)
        
        if analyze_js and self.config.js_analysis:
            await self._analyze_javascript()
        
        return self._get_results(domain)
    
    async def _collect_osint(self, domain: str):
        if not self.silent_mode:
            logger.info("Starting OSINT collection from all sources...")
        
        collector_classes = [
            (WaybackCollector, self.config.wayback),
            (URLScanCollector, self.config.urlscan),
            (AlienVaultCollector, self.config.alienvault),
            (CommonCrawlCollector, self.config.commoncrawl),
            (LiveDiscoveryCollector, self.config.live_discovery),
        ]
        
        tasks = []
        collectors = []
        
        connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=3,
            enable_cleanup_closed=True,
            ssl=False
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            for CollectorClass, config in collector_classes:
                if config.enabled:
                    collector = CollectorClass(config, silent_mode=self.silent_mode)
                    collector.session = session
                    collectors.append(collector)
                    tasks.append(collector.collect(domain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for collector, result in zip(collectors, results):
                if isinstance(result, Exception):
                    if not self.silent_mode:
                        logger.error(f"Collector {collector.name} failed: {result}")
                    self.collected_data[collector.name] = CollectedData(
                        source=collector.name,
                        errors=[str(result)]
                    )
                else:
                    self.collected_data[collector.name] = result
        
        total_urls = sum(len(d.urls) for d in self.collected_data.values())
        total_subdomains = set()
        for d in self.collected_data.values():
            total_subdomains.update(d.subdomains)
        
        if not self.silent_mode:
            logger.info(f"OSINT collection complete: {total_urls} URLs, {len(total_subdomains)} subdomains")
    
    def _categorize_urls(self, domain: str):
        if not self.silent_mode:
            logger.info("Categorizing collected URLs...")
        
        all_urls = set()
        main_domain_urls = []
        subdomain_urls = {}
        js_files = set()
        endpoints = []
        external_urls = []
        
        for data in self.collected_data.values():
            for url in data.urls:
                normalized = self.normalizer.normalize_url(url)
                if not normalized:
                    continue
                
                all_urls.add(normalized)
                
                category = self.normalizer.categorize_url(normalized, domain)
                
                if category == 'javascript':
                    js_files.add(normalized)
                elif category == 'main_domain':
                    main_domain_urls.append(normalized)
                elif category == 'subdomain':
                    subdomain, _, full = self.normalizer.extract_domain_parts(normalized)
                    if full not in subdomain_urls:
                        subdomain_urls[full] = []
                    subdomain_urls[full].append(normalized)
                elif category == 'external':
                    external_urls.append(normalized)
                
                if self.normalizer.is_interesting_endpoint(normalized):
                    endpoints.append(normalized)
            
            js_files.update(data.js_files)
            endpoints.extend(data.endpoints)
        
        self.categorized_urls = {
            'all': list(all_urls),
            'main_domain': list(set(main_domain_urls)),
            'subdomain_urls': {k: list(set(v)) for k, v in subdomain_urls.items()},
            'javascript': list(js_files),
            'endpoints': list(set(endpoints)),
            'external': list(set(external_urls))
        }
        
        if not self.silent_mode:
            logger.info(f"Categorized: {len(main_domain_urls)} main domain, "
                       f"{len(subdomain_urls)} subdomains, {len(js_files)} JS files")
    
    async def _analyze_javascript(self):
        js_files = self.categorized_urls.get('javascript', [])
        
        if not js_files:
            if not self.silent_mode:
                logger.info("No JavaScript files to analyze")
            return
        
        if not self.silent_mode:
            logger.info(f"Analyzing {len(js_files)} JavaScript files...")
        
        analyzer = JSAnalyzer(max_size=self.config.max_js_size, silent_mode=self.silent_mode)
        
        connector = aiohttp.TCPConnector(
            limit=5,
            limit_per_host=2,
            ssl=False
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            self.js_results = await analyzer.analyze_urls(js_files[:30], session)
        
        successful = sum(1 for r in self.js_results if r.success)
        total_secrets = sum(len(r.secrets) for r in self.js_results)
        
        if not self.silent_mode:
            logger.info(f"JavaScript analysis complete: {successful}/{len(js_files)} files, "
                       f"{total_secrets} potential secrets found")
    
    def _get_results(self, domain: str) -> Dict:
        return {
            'domain': domain,
            'collected_data': self.collected_data,
            'js_results': self.js_results,
            'categorized_urls': self.categorized_urls
        }
    
    def get_display_results(self) -> Dict:
        """Get results formatted for web display."""
        all_subdomains = set()
        for data in self.collected_data.values():
            all_subdomains.update(data.subdomains)
        
        all_secrets = []
        for result in self.js_results:
            for secret in result.secrets:
                all_secrets.append(secret.to_dict())
        
        high_confidence = sum(1 for s in all_secrets if s.get('confidence') == 'high')
        
        all_endpoints = []
        for result in self.js_results:
            all_endpoints.extend(result.api_endpoints)
        all_endpoints = list(set(all_endpoints))
        
        return {
            'stats': {
                'total_urls': len(self.categorized_urls.get('all', [])),
                'total_subdomains': len(all_subdomains),
                'total_js_files': len(self.categorized_urls.get('javascript', [])),
                'total_endpoints': len(self.categorized_urls.get('endpoints', [])) + len(all_endpoints),
                'total_secrets': len(all_secrets),
                'high_confidence': high_confidence
            },
            'urls': self.categorized_urls.get('main_domain', [])[:100],
            'subdomains': list(all_subdomains),
            'endpoints': (self.categorized_urls.get('endpoints', []) + all_endpoints)[:100],
            'secrets': all_secrets,
            'js_files': self.categorized_urls.get('javascript', [])[:50]
        }
    
    def export_json(self, domain: str, output_dir: str = None) -> str:
        exporter = JSONExporter(output_dir or self.config.output_dir)
        return exporter.export_full_report(
            domain,
            self.collected_data,
            self.js_results,
            self.categorized_urls
        )
    
    def export_html(self, domain: str, output_dir: str = None) -> str:
        generator = HTMLReportGenerator()
        return generator.generate(
            domain,
            self.collected_data,
            self.js_results,
            self.categorized_urls,
            output_dir or self.config.output_dir
        )


async def run_recon(target: str, config: Config = None, 
                    analyze_js: bool = True, silent_mode: bool = True) -> ReconEngine:
    engine = ReconEngine(config, silent_mode=silent_mode)
    await engine.run(target, analyze_js)
    return engine
