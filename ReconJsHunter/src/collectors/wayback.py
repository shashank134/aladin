"""
Wayback Machine (Web Archive) collector.
Uses the CDX API to retrieve historical URLs with stealth capabilities.
Creates fetchable archive URLs for JavaScript files.
"""

import re
from typing import List
from urllib.parse import quote

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class WaybackCollector(BaseCollector):
    
    name = "wayback"
    
    CDX_API = "https://web.archive.org/cdx/search/cdx"
    ARCHIVE_BASE = "https://web.archive.org/web"
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    def _make_archive_url(self, timestamp: str, original_url: str) -> str:
        """Convert original URL to fetchable Wayback archive URL."""
        return f"{self.ARCHIVE_BASE}/{timestamp}id_/{original_url}"
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Fetching URLs from Wayback Machine (with full pagination)...")
        
        try:
            seen_urls = set()
            page_count = 0
            max_pages = 20
            
            while page_count < max_pages:
                params = {
                    'url': f'*.{domain}/*',
                    'output': 'json',
                    'fl': 'original,mimetype,statuscode,timestamp',
                    'collapse': 'urlkey',
                    'filter': 'statuscode:200',
                    'pageSize': 10000,
                    'page': page_count
                }
                
                query_string = '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
                url = f"{self.CDX_API}?{query_string}"
                
                try:
                    response = await self.rate_limiter.request(
                        self.session, url, timeout=60
                    )
                    
                    if not response or response.status != 200:
                        if page_count == 0:
                            data.errors.append(f"Failed to fetch from Wayback CDX API")
                        break
                    
                    try:
                        results = await response.json()
                    except Exception:
                        text = await response.text()
                        lines = text.strip().split('\n')
                        results = []
                        for line in lines:
                            if line:
                                parts = line.split()
                                if len(parts) >= 4:
                                    results.append(parts)
                    
                    if not results:
                        break
                    
                    header_row = None
                    if isinstance(results[0], list) and len(results[0]) >= 2:
                        if 'original' in str(results[0][0]).lower():
                            header_row = results[0]
                            results = results[1:]
                    
                    if not results:
                        break
                    
                    entries_in_page = 0
                    
                    for entry in results:
                        try:
                            if isinstance(entry, list) and len(entry) >= 4:
                                original_url = entry[0]
                                mimetype = entry[1] if len(entry) > 1 else ''
                                timestamp = entry[3] if len(entry) > 3 else ''
                            elif isinstance(entry, dict):
                                original_url = entry.get('original', '')
                                mimetype = entry.get('mimetype', '')
                                timestamp = entry.get('timestamp', '')
                            else:
                                continue
                            
                            normalized = normalizer.normalize_url(original_url)
                            if not normalized or normalized in seen_urls:
                                continue
                            
                            seen_urls.add(normalized)
                            entries_in_page += 1
                            data.urls.append(normalized)
                            
                            is_js = 'javascript' in mimetype.lower() or normalized.endswith('.js')
                            if is_js and timestamp:
                                archive_url = self._make_archive_url(timestamp, original_url)
                                data.js_files.append(archive_url)
                            elif is_js:
                                data.js_files.append(normalized)
                            
                            subdomain, root, full = normalizer.extract_domain_parts(normalized)
                            if subdomain and root.lower() == domain.lower():
                                data.subdomains.add(full)
                            
                            if normalizer.is_interesting_endpoint(normalized):
                                data.endpoints.append(normalized)
                        
                        except Exception:
                            continue
                    
                    if entries_in_page < 10000:
                        break
                    
                    page_count += 1
                
                except Exception as e:
                    if not self.silent_mode:
                        logger.debug(f"Wayback page {page_count} error: {e}")
                    break
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files, {len(data.subdomains)} subdomains from {page_count+1} pages")
            
        except Exception as e:
            error_msg = f"Error collecting from Wayback: {e}"
            data.errors.append(error_msg)
            if not self.silent_mode:
                logger.error(error_msg)
        
        return data
