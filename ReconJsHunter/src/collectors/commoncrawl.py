"""
Common Crawl collector.
Uses the Common Crawl index API to retrieve massive historical URL datasets.
This is critical for discovering 100k+ URLs on large domains.
"""

import json
from typing import List
from urllib.parse import quote

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class CommonCrawlCollector(BaseCollector):
    
    name = "commoncrawl"
    
    # Common Crawl index API
    CDX_API = "https://index.commoncrawl.org/search/cdx"
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Fetching URLs from Common Crawl...")
        
        try:
            # Use Common Crawl's powerful index API with pagination
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'original,mimetype,status',
                'collapse': 'original',
                'filter': 'status:200',
                'matchType': 'domain',
                'pageSize': 10000  # Max page size
            }
            
            seen_urls = set()
            page_count = 0
            max_pages = 10  # Reasonable limit
            
            # Paginate through Common Crawl results
            while page_count < max_pages:
                params['page'] = page_count
                
                query_string = '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
                url = f"{self.CDX_API}?{query_string}"
                
                try:
                    response = await self.rate_limiter.request(
                        self.session, url, timeout=60
                    )
                    
                    if not response or response.status != 200:
                        break
                    
                    result = await response.json()
                    
                    if not result or not isinstance(result, dict):
                        break
                    
                    results = result.get('results', [])
                    if not results:
                        break
                    
                    # First item is header
                    if results[0] == ['original', 'mimetype', 'status']:
                        results = results[1:]
                    
                    for entry in results:
                        try:
                            if isinstance(entry, list) and len(entry) >= 1:
                                original_url = entry[0]
                                mimetype = entry[1] if len(entry) > 1 else ''
                                
                                normalized = normalizer.normalize_url(original_url)
                                if not normalized or normalized in seen_urls:
                                    continue
                                
                                seen_urls.add(normalized)
                                data.urls.append(normalized)
                                
                                if 'javascript' in mimetype.lower() or normalized.endswith('.js'):
                                    data.js_files.append(normalized)
                                
                                subdomain, root, full = normalizer.extract_domain_parts(normalized)
                                if subdomain and root.lower() == domain.lower():
                                    data.subdomains.add(full)
                                
                                if normalizer.is_interesting_endpoint(normalized):
                                    data.endpoints.append(normalized)
                        
                        except Exception:
                            continue
                    
                    if len(results) < 10000:
                        break  # No more results
                    
                    page_count += 1
                    
                except Exception as e:
                    if not self.silent_mode:
                        logger.debug(f"Common Crawl page {page_count} error: {e}")
                    break
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files, {len(data.subdomains)} subdomains from {page_count} pages")
            
        except Exception as e:
            error_msg = f"Error collecting from Common Crawl: {e}"
            data.errors.append(error_msg)
            if not self.silent_mode:
                logger.error(error_msg)
        
        return data
