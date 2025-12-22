"""
Main reconnaissance engine.
Orchestrates all collectors and analyzers with stealth and silent mode support.
Enhanced with scan caching and resume capability.
"""

import asyncio
import signal
from typing import Dict, List, Set
import aiohttp

from src.core.config import Config, get_default_config
from src.core.normalizer import URLNormalizer, normalize_input
from src.core.logger import logger, set_silent
from src.core.scan_cache import ScanCache
from src.collectors.base import CollectedData
from src.collectors.wayback import WaybackCollector
from src.collectors.urlscan import URLScanCollector
from src.collectors.alienvault import AlienVaultCollector
from src.collectors.commoncrawl import CommonCrawlCollector
from src.collectors.live_discovery import LiveDiscoveryCollector
from src.collectors.search_engines import GoogleCollector, BingCollector, DuckDuckGoCollector
from src.collectors.recursive_expander import RecursiveExpander
from src.models import JsAnalysisResult
from src.pipelines.js_analysis.runner import JsAnalysisRunner
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
        self.js_result: JsAnalysisResult = None
        self.categorized_urls: Dict[str, List[str]] = {}
        
        self._scan_cache: ScanCache = None
        self._interrupted = False
        self._original_sigint = None
    
    def _setup_signal_handler(self):
        import threading
        if threading.current_thread() is not threading.main_thread():
            return
        
        try:
            self._original_sigint = signal.getsignal(signal.SIGINT)
            
            def handle_interrupt(signum, frame):
                self._interrupted = True
                if not self.silent_mode:
                    logger.warning("Interrupt received, saving state before exit...")
                if self._scan_cache and self.collected_data:
                    self._scan_cache.save_state(self.collected_data, progress="interrupted")
                    if not self.silent_mode:
                        logger.info("Scan state saved. Use --resume to continue.")
                if self._original_sigint and callable(self._original_sigint):
                    self._original_sigint(signum, frame)
                else:
                    raise KeyboardInterrupt
            
            signal.signal(signal.SIGINT, handle_interrupt)
        except ValueError:
            pass
    
    def _restore_signal_handler(self):
        import threading
        if threading.current_thread() is not threading.main_thread():
            return
        
        try:
            if self._original_sigint is not None:
                signal.signal(signal.SIGINT, self._original_sigint)
        except ValueError:
            pass
    
    def _restore_from_cache(self, cached_data: Dict[str, Dict]):
        for source_name, data in cached_data.items():
            self.collected_data[source_name] = CollectedData(
                source=source_name,
                urls=list(data.get('urls', [])),
                subdomains=set(data.get('subdomains', [])),
                js_files=list(data.get('js_files', [])),
                endpoints=list(data.get('endpoints', [])),
                errors=list(data.get('errors', []))
            )
    
    async def run(self, target: str, analyze_js: bool = True, resume: bool = False) -> Dict:
        domain = self.normalizer.normalize_domain(target)
        
        self._scan_cache = ScanCache(self.config.output_dir, domain)
        
        self._setup_signal_handler()
        
        try:
            if resume and self._scan_cache.is_resumable():
                cache_info = self._scan_cache.get_cache_info()
                cached_sources = self._scan_cache.get_cached_sources()
                
                if not self.silent_mode:
                    logger.info(f"Resuming scan for: {domain}")
                    logger.info(f"Found {len(cached_sources)} cached sources: {', '.join(cached_sources)}")
                
                cached_data = self._scan_cache.get_all_cached_data()
                self._restore_from_cache(cached_data)
            else:
                if not self.silent_mode:
                    logger.info(f"Starting reconnaissance for: {domain}")
            
            await self._collect_osint(domain, resume=resume)
            
            if self._interrupted:
                return self._get_results(domain)
            
            self._categorize_urls(domain)
            
            if analyze_js and self.config.js_analysis:
                await self._analyze_javascript()
            
            self._scan_cache.mark_completed()
            self._scan_cache.cleanup()
            
            return self._get_results(domain)
        
        finally:
            self._restore_signal_handler()
    
    async def _collect_osint(self, domain: str, resume: bool = False):
        if not self.silent_mode:
            logger.info("Starting OSINT collection from all sources...")
        
        cached_sources = []
        if resume and self._scan_cache:
            cached_sources = self._scan_cache.get_cached_sources()
        
        collector_classes = [
            (WaybackCollector, self.config.wayback),
            (URLScanCollector, self.config.urlscan),
            (AlienVaultCollector, self.config.alienvault),
            (CommonCrawlCollector, self.config.commoncrawl),
            (LiveDiscoveryCollector, self.config.live_discovery),
            (GoogleCollector, self.config.google),
            (BingCollector, self.config.bing),
            (DuckDuckGoCollector, self.config.duckduckgo),
        ]
        
        connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=3,
            enable_cleanup_closed=True
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            for CollectorClass, config in collector_classes:
                if self._interrupted:
                    break
                
                if not config.enabled:
                    continue
                
                collector = CollectorClass(config, silent_mode=self.silent_mode)
                
                if collector.name in cached_sources:
                    if not self.silent_mode:
                        logger.info(f"Skipping {collector.name} (cached)")
                    continue
                
                collector.session = session
                
                try:
                    if not self.silent_mode:
                        logger.info(f"Collecting from {collector.name}...")
                    
                    result = await collector.collect(domain)
                    self.collected_data[collector.name] = result
                    
                    if self._scan_cache:
                        self._scan_cache.save_state(self.collected_data)
                    
                except Exception as e:
                    if not self.silent_mode:
                        logger.error(f"Collector {collector.name} failed: {e}")
                    self.collected_data[collector.name] = CollectedData(
                        source=collector.name,
                        errors=[str(e)]
                    )
                    if self._scan_cache:
                        self._scan_cache.save_state(self.collected_data)
        
        total_urls = sum(len(d.urls) for d in self.collected_data.values())
        total_subdomains = set()
        for d in self.collected_data.values():
            total_subdomains.update(d.subdomains)
        
        if not self.silent_mode:
            logger.info(f"OSINT collection complete: {total_urls} URLs, {len(total_subdomains)} subdomains")
        
        if not self._interrupted and self.config.recursive_expansion.enabled:
            await self._run_recursive_expansion(domain)
    
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
            
            endpoints.extend(data.endpoints)
        
        for data in self.collected_data.values():
            if data.source == 'live_discovery':
                for js in data.js_files:
                    if 'web.archive.org' not in js:
                        js_files.add(js)
        
        for data in self.collected_data.values():
            if data.source != 'live_discovery':
                for js in data.js_files:
                    js_files.add(js)
        
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
    
    async def _run_recursive_expansion(self, domain: str):
        if not self.silent_mode:
            logger.info("Starting recursive URL expansion...")
        
        all_urls = []
        for data in self.collected_data.values():
            all_urls.extend(data.urls[:50])
        
        all_urls = list(set(all_urls))[:100]
        
        if not all_urls:
            return
        
        connector = aiohttp.TCPConnector(
            limit=5,
            limit_per_host=2,
            enable_cleanup_closed=True
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            expander = RecursiveExpander(self.config.recursive_expansion, silent_mode=self.silent_mode)
            expander.session = session
            expanded_data = await expander.expand_urls(all_urls, domain, session)
            
            if expanded_data.urls:
                self.collected_data['recursive_expander'] = expanded_data
                
                if self._scan_cache:
                    self._scan_cache.save_state(self.collected_data)
                
                if not self.silent_mode:
                    logger.info(f"Recursive expansion found {len(expanded_data.urls)} additional URLs")
    
    async def _analyze_javascript(self):
        js_files = self.categorized_urls.get('javascript', [])
        
        if not js_files:
            if not self.silent_mode:
                logger.info("No JavaScript files to analyze")
            return
        
        if not self.silent_mode:
            logger.info(f"Analyzing {len(js_files)} JavaScript files...")
        
        runner = JsAnalysisRunner(
            output_dir=self.config.output_dir,
            silent_mode=self.silent_mode,
            max_file_size=self.config.max_js_size
        )
        
        domain = list(self.collected_data.keys())[0] if self.collected_data else "unknown"
        self.js_result = await runner.run_async(target=domain, js_urls=js_files[:200])
        
        successful = sum(1 for f in self.js_result.files_analyzed if f.status == 'success')
        total_findings = self.js_result.total_findings
        
        if not self.silent_mode:
            logger.info(f"JavaScript analysis complete: {successful}/{len(js_files)} files, "
                       f"{total_findings} potential findings found")
    
    def _get_results(self, domain: str) -> Dict:
        return {
            'domain': domain,
            'collected_data': self.collected_data,
            'js_result': self.js_result,
            'categorized_urls': self.categorized_urls
        }
    
    def get_display_results(self) -> Dict:
        """Get results formatted for web display."""
        all_subdomains = set()
        for data in self.collected_data.values():
            all_subdomains.update(data.subdomains)
        
        all_findings = []
        all_endpoints = []
        if self.js_result:
            for file_analysis in self.js_result.files_analyzed:
                for finding in file_analysis.findings:
                    finding_dict = finding.to_dict()
                    finding_dict['source_file'] = file_analysis.url
                    all_findings.append(finding_dict)
                    if finding.category == 'INTERNAL_PATHS':
                        all_endpoints.append(finding.value)
        
        high_confidence = sum(1 for f in all_findings if f.get('confidence') == 'high')
        all_endpoints = list(set(all_endpoints))
        
        return {
            'stats': {
                'total_urls': len(self.categorized_urls.get('all', [])),
                'total_subdomains': len(all_subdomains),
                'total_js_files': len(self.categorized_urls.get('javascript', [])),
                'total_endpoints': len(self.categorized_urls.get('endpoints', [])) + len(all_endpoints),
                'total_secrets': len(all_findings),
                'high_confidence': high_confidence
            },
            'urls': self.categorized_urls.get('main_domain', [])[:100],
            'subdomains': list(all_subdomains),
            'endpoints': (self.categorized_urls.get('endpoints', []) + all_endpoints)[:100],
            'secrets': all_findings,
            'js_files': self.categorized_urls.get('javascript', [])[:50]
        }
    
    def check_resumable(self, target: str) -> Dict:
        """Check if a resumable scan exists for the target."""
        domain = self.normalizer.normalize_domain(target)
        cache = ScanCache(self.config.output_dir, domain)
        
        if cache.is_resumable():
            return cache.get_cache_info()
        return None
    
    def export_json(self, domain: str, output_dir: str = None) -> str:
        exporter = JSONExporter(output_dir or self.config.output_dir)
        return exporter.export_full_report(
            domain,
            self.collected_data,
            self.js_result,
            self.categorized_urls
        )
    
    def export_html(self, domain: str, output_dir: str = None) -> str:
        generator = HTMLReportGenerator()
        return generator.generate(
            domain,
            self.collected_data,
            self.js_result,
            self.categorized_urls,
            output_dir or self.config.output_dir
        )


async def run_recon(target: str, config: Config = None, 
                    analyze_js: bool = True, silent_mode: bool = True,
                    resume: bool = False) -> ReconEngine:
    engine = ReconEngine(config, silent_mode=silent_mode)
    await engine.run(target, analyze_js, resume=resume)
    return engine
