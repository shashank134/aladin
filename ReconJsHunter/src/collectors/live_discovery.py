"""
Live discovery collector.
Fetches robots.txt, sitemap.xml, and performs HTML parsing for links.
Critical for discovering live URLs that may not be in archives.
"""

import re
from typing import Set
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class LiveDiscoveryCollector(BaseCollector):
    
    name = "live_discovery"
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        base_url = f"https://{domain}"
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Discovering live URLs (robots.txt, sitemap, HTML)...")
        
        try:
            # Fetch robots.txt
            await self._fetch_robots(base_url, data, normalizer, domain)
            
            # Fetch sitemap.xml
            await self._fetch_sitemap(base_url, data, normalizer, domain)
            
            # Try to fetch home page and extract links
            await self._fetch_and_parse_html(base_url, data, normalizer, domain)
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files")
            
        except Exception as e:
            if not self.silent_mode:
                logger.debug(f"Live discovery error: {e}")
        
        return data
    
    async def _fetch_robots(self, base_url: str, data: CollectedData, 
                           normalizer: URLNormalizer, domain: str):
        """Extract URLs from robots.txt"""
        try:
            url = f"{base_url}/robots.txt"
            response = await self.rate_limiter.request(self.session, url, timeout=10)
            
            if response and response.status == 200:
                text = await response.text()
                
                # Extract Allow/Disallow paths
                for line in text.split('\n'):
                    if line.strip().startswith(('Allow:', 'Disallow:')):
                        path = line.split(':', 1)[1].strip()
                        if path and not path.startswith('#'):
                            full_url = urljoin(base_url, path)
                            normalized = normalizer.normalize_url(full_url)
                            if normalized:
                                data.urls.append(normalized)
                
                # Extract Sitemap directives
                for line in text.split('\n'):
                    if line.strip().startswith('Sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        if sitemap_url:
                            await self._fetch_sitemap_from_url(sitemap_url, data, normalizer, domain)
        
        except Exception:
            pass
    
    async def _fetch_sitemap(self, base_url: str, data: CollectedData,
                            normalizer: URLNormalizer, domain: str):
        """Fetch and parse sitemap.xml"""
        try:
            urls_to_try = [
                f"{base_url}/sitemap.xml",
                f"{base_url}/sitemap_index.xml",
                f"{base_url}/sitemap1.xml"
            ]
            
            for sitemap_url in urls_to_try:
                await self._fetch_sitemap_from_url(sitemap_url, data, normalizer, domain)
        
        except Exception:
            pass
    
    async def _fetch_sitemap_from_url(self, sitemap_url: str, data: CollectedData,
                                     normalizer: URLNormalizer, domain: str):
        """Fetch specific sitemap URL"""
        try:
            response = await self.rate_limiter.request(self.session, sitemap_url, timeout=10)
            
            if not response or response.status != 200:
                return
            
            text = await response.text()
            
            try:
                root = ET.fromstring(text)
                
                # Handle sitemap index
                for sitemap_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                    loc = sitemap_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc is not None and loc.text:
                        await self._fetch_sitemap_from_url(loc.text, data, normalizer, domain)
                
                # Handle regular sitemaps
                for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                    loc = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc is not None and loc.text:
                        normalized = normalizer.normalize_url(loc.text)
                        if normalized:
                            data.urls.append(normalized)
                            
                            if normalized.endswith('.js'):
                                data.js_files.append(normalized)
            
            except ET.ParseError:
                # Try regex fallback
                urls = re.findall(r'<loc>(https?://[^<]+)</loc>', text)
                for url in urls:
                    normalized = normalizer.normalize_url(url)
                    if normalized:
                        data.urls.append(normalized)
        
        except Exception:
            pass
    
    async def _fetch_and_parse_html(self, base_url: str, data: CollectedData,
                                   normalizer: URLNormalizer, domain: str):
        """Fetch homepage and extract links"""
        try:
            response = await self.rate_limiter.request(self.session, base_url, timeout=10)
            
            if not response or response.status != 200:
                return
            
            html = await response.text()
            
            # Extract href links
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)
            for href in hrefs:
                if not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    full_url = urljoin(base_url, href)
                    normalized = normalizer.normalize_url(full_url)
                    if normalized and normalizer.is_same_domain(full_url, domain):
                        data.urls.append(normalized)
                        
                        if normalized.endswith('.js'):
                            data.js_files.append(normalized)
            
            # Extract src scripts
            scripts = re.findall(r'src=["\']([^"\']+)["\']', html)
            for script in scripts:
                if script and not script.startswith(('#', 'javascript:', 'data:')):
                    full_url = urljoin(base_url, script)
                    normalized = normalizer.normalize_url(full_url)
                    if normalized:
                        data.js_files.append(normalized)
        
        except Exception:
            pass
