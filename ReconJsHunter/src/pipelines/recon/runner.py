"""
Reconnaissance Runner - Phase 1 of the modular pipeline.
Orchestrates URL collection from all collectors without JavaScript analysis.
"""

import asyncio
from typing import Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urlparse

from src.core.config import Config, get_default_config
from src.core.normalizer import URLNormalizer
from src.core.logger import logger, set_silent
from src.models import ReconResult, DiscoveredUrl, UrlType
from src.services.datastore import DataStore
from src.collectors.base import CollectedData
from src.collectors.wayback import WaybackCollector
from src.collectors.urlscan import URLScanCollector
from src.collectors.alienvault import AlienVaultCollector
from src.collectors.commoncrawl import CommonCrawlCollector
from src.collectors.live_discovery import LiveDiscoveryCollector
from src.collectors.search_engines import GoogleCollector, BingCollector, DuckDuckGoCollector


class ReconRunner:
    
    def __init__(self, config: Optional[Config] = None, silent_mode: bool = False, output_dir: str = "recon_output"):
        self.config = config or get_default_config()
        self.silent_mode = silent_mode
        self.normalizer = URLNormalizer()
        self.datastore = DataStore(output_dir)
        
        if silent_mode:
            set_silent(True)
    
    def _classify_url_type(self, url: str) -> UrlType:
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        if path.endswith('.js'):
            return UrlType.JAVASCRIPT
        
        if any(pattern in path for pattern in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/']):
            return UrlType.API
        
        if any(pattern in path for pattern in ['/static/', '/assets/', '/dist/', '/build/']):
            return UrlType.STATIC
        
        static_extensions = {'.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', 
                           '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf',
                           '.webp', '.avif', '.bmp', '.tiff', '.mov'}
        if any(path.endswith(ext) for ext in static_extensions):
            return UrlType.STATIC
        
        if parsed.path and not path.endswith('/'):
            return UrlType.ENDPOINT
        
        return UrlType.OTHER
    
    def _create_discovered_url(self, url: str, source: str, target_domain: str) -> DiscoveredUrl:
        subdomain, root_domain, full_domain = self.normalizer.extract_domain_parts(url)
        
        return DiscoveredUrl(
            url=url,
            domain=root_domain,
            subdomain=subdomain if subdomain else None,
            source=source,
            url_type=self._classify_url_type(url),
            discovered_at=datetime.now().isoformat(),
            metadata={}
        )
    
    def _group_urls_by_domain(self, discovered_urls: List[DiscoveredUrl]) -> Dict[str, List[DiscoveredUrl]]:
        grouped: Dict[str, List[DiscoveredUrl]] = {}
        
        for url_obj in discovered_urls:
            if url_obj.subdomain:
                key = f"{url_obj.subdomain}.{url_obj.domain}"
            else:
                key = url_obj.domain
            
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(url_obj)
        
        return grouped
    
    async def _run_collector(self, collector_class, config, domain: str, source_name: str) -> CollectedData:
        try:
            async with collector_class(config, silent_mode=self.silent_mode) as collector:
                if collector.is_enabled():
                    return await collector.collect(domain)
                return CollectedData(source=source_name)
        except Exception as e:
            if not self.silent_mode:
                logger.error(f"Error running {source_name}: {e}")
            data = CollectedData(source=source_name)
            data.errors.append(str(e))
            return data
    
    async def run(self, target: str) -> ReconResult:
        domain = self.normalizer.normalize_domain(target)
        scan_id = self.datastore.generate_scan_id()
        started_at = datetime.now().isoformat()
        
        if not self.silent_mode:
            logger.info(f"Starting reconnaissance for: {domain}")
            logger.info(f"Scan ID: {scan_id}")
        
        collector_tasks = [
            self._run_collector(WaybackCollector, self.config.wayback, domain, "wayback"),
            self._run_collector(URLScanCollector, self.config.urlscan, domain, "urlscan"),
            self._run_collector(AlienVaultCollector, self.config.alienvault, domain, "alienvault"),
            self._run_collector(CommonCrawlCollector, self.config.commoncrawl, domain, "commoncrawl"),
            self._run_collector(LiveDiscoveryCollector, self.config.live_discovery, domain, "live_discovery"),
            self._run_collector(GoogleCollector, self.config.google, domain, "google"),
            self._run_collector(BingCollector, self.config.bing, domain, "bing"),
            self._run_collector(DuckDuckGoCollector, self.config.duckduckgo, domain, "duckduckgo"),
        ]
        
        results = await asyncio.gather(*collector_tasks, return_exceptions=True)
        
        all_urls: Dict[str, DiscoveredUrl] = {}
        sources_used: Set[str] = set()
        
        for result in results:
            if isinstance(result, Exception):
                if not self.silent_mode:
                    logger.error(f"Collector exception: {result}")
                continue
            
            if isinstance(result, CollectedData):
                source = result.source
                
                if result.urls:
                    sources_used.add(source)
                
                for url in result.urls:
                    normalized = self.normalizer.normalize_url(url, domain)
                    if normalized and normalized not in all_urls:
                        all_urls[normalized] = self._create_discovered_url(normalized, source, domain)
                
                for js_url in result.js_files:
                    normalized = self.normalizer.normalize_url(js_url, domain)
                    if normalized and normalized not in all_urls:
                        discovered = self._create_discovered_url(normalized, source, domain)
                        discovered.url_type = UrlType.JAVASCRIPT
                        all_urls[normalized] = discovered
        
        discovered_urls = list(all_urls.values())
        
        if not self.silent_mode:
            logger.info(f"Total unique URLs collected: {len(discovered_urls)}")
        
        urls_by_domain = self._group_urls_by_domain(discovered_urls)
        
        result = ReconResult(
            target=domain,
            scan_id=scan_id,
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            urls_by_domain=urls_by_domain,
            total_urls=len(discovered_urls),
            sources_used=list(sources_used)
        )
        
        filepath = self.datastore.save_recon_result(result)
        
        if not self.silent_mode:
            logger.info(f"Recon results saved to: {filepath}")
            logger.info(f"Domains found: {len(urls_by_domain)}")
            logger.info(f"Sources used: {', '.join(sources_used)}")
            
            type_counts = {}
            for url_obj in discovered_urls:
                t = url_obj.url_type.value
                type_counts[t] = type_counts.get(t, 0) + 1
            logger.info(f"URL types: {type_counts}")
        
        return result
    
    def run_sync(self, target: str) -> ReconResult:
        return asyncio.run(self.run(target))
