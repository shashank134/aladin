"""
URLScan.io collector.
Uses the URLScan API to retrieve scan results and discovered URLs with stealth capabilities.
"""

from typing import List, Dict
from urllib.parse import quote

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class URLScanCollector(BaseCollector):
    
    name = "urlscan"
    
    SEARCH_API = "https://urlscan.io/api/v1/search/"
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Searching URLScan.io database...")
        
        try:
            headers = {}
            if self.config.api_key:
                headers['API-Key'] = self.config.api_key
            
            query = f"domain:{domain}"
            url = f"{self.SEARCH_API}?q={quote(query)}&size=500"
            
            response = await self.rate_limiter.request(
                self.session, url, headers=headers, timeout=60
            )
            
            if not response:
                data.errors.append("Failed to fetch from URLScan API")
                return data
            
            if response.status == 429:
                data.errors.append("Rate limited by URLScan API")
                return data
            
            if response.status != 200:
                data.errors.append(f"URLScan API returned status {response.status}")
                return data
            
            results = await response.json()
            
            if not results or 'results' not in results:
                return data
            
            for result in results.get('results', [])[:50]:
                try:
                    page = result.get('page', {})
                    
                    page_url = page.get('url', '')
                    if page_url:
                        normalized = normalizer.normalize_url(page_url)
                        if normalized:
                            data.urls.append(normalized)
                            
                            subdomain, root, full = normalizer.extract_domain_parts(normalized)
                            if subdomain and root.lower() == domain.lower():
                                data.subdomains.add(full)
                    
                    page_domain = page.get('domain', '')
                    if page_domain and domain in page_domain:
                        subdomain, root, full = normalizer.extract_domain_parts(page_domain)
                        if subdomain:
                            data.subdomains.add(full)
                    
                    result_id = result.get('_id')
                    if result_id and len(data.urls) < 200:
                        await self._fetch_scan_details(result_id, data, normalizer, domain)
                
                except Exception:
                    continue
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files, {len(data.subdomains)} subdomains")
            
        except Exception as e:
            error_msg = f"Error collecting from URLScan: {e}"
            data.errors.append(error_msg)
            if not self.silent_mode:
                logger.error(error_msg)
        
        return data
    
    async def _fetch_scan_details(self, scan_id: str, data: CollectedData, 
                                   normalizer: URLNormalizer, domain: str):
        try:
            url = f"https://urlscan.io/api/v1/result/{scan_id}/"
            
            response = await self.rate_limiter.request(
                self.session, url, timeout=30
            )
            
            if not response or response.status != 200:
                return
            
            result = await response.json()
            
            for request in result.get('data', {}).get('requests', [])[:50]:
                req_url = request.get('request', {}).get('url', '')
                if req_url:
                    normalized = normalizer.normalize_url(req_url)
                    if normalized:
                        data.urls.append(normalized)
                        
                        if normalized.endswith('.js'):
                            data.js_files.append(normalized)
                        
                        if normalizer.is_interesting_endpoint(normalized):
                            data.endpoints.append(normalized)
            
            for link in result.get('data', {}).get('links', [])[:30]:
                href = link.get('href', '')
                if href:
                    normalized = normalizer.normalize_url(href)
                    if normalized:
                        data.urls.append(normalized)
        
        except Exception:
            pass
