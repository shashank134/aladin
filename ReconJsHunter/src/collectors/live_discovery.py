"""
Live discovery collector.
Fetches robots.txt, sitemap.xml, and performs HTML parsing for links.
Critical for discovering live URLs that may not be in archives.
Enhanced: Crawls multiple internal pages to find more live JS files.
"""

import re
import asyncio
from typing import Set, List
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer


class LiveDiscoveryCollector(BaseCollector):
    
    name = "live_discovery"
    
    NON_HTML_EXTENSIONS = {
        '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg',
        '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.zip', '.tar',
        '.gz', '.rar', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.webp', '.avif', '.bmp', '.tiff', '.mov', '.avi', '.wmv', '.flv',
        '.xml', '.json', '.txt', '.csv', '.js'
    }
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
        self.max_pages_to_crawl = 20
        self.visited_pages: Set[str] = set()
        self.crawl_queue: List[str] = []
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        base_url = f"https://{domain}"
        self.visited_pages = set()
        self.crawl_queue = []
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Discovering live URLs (robots.txt, sitemap, HTML)...")
        
        try:
            await self._fetch_robots(base_url, data, normalizer, domain)
            await self._fetch_sitemap(base_url, data, normalizer, domain)
            await self._crawl_site(base_url, data, normalizer, domain)
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files from {len(self.visited_pages)} pages")
            
        except Exception as e:
            if not self.silent_mode:
                logger.debug(f"Live discovery error: {e}")
        
        return data
    
    def _is_likely_html_page(self, url: str) -> bool:
        """Check if URL is likely an HTML page (not a resource file)"""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        if any(path_lower.endswith(ext) for ext in self.NON_HTML_EXTENSIONS):
            return False
        
        if not parsed.path or parsed.path == '/' or parsed.path.endswith('/'):
            return True
        
        last_segment = parsed.path.split('/')[-1]
        if '.' not in last_segment or last_segment.endswith('.html') or last_segment.endswith('.htm') or last_segment.endswith('.php') or last_segment.endswith('.asp') or last_segment.endswith('.aspx'):
            return True
        
        return False
    
    async def _fetch_robots(self, base_url: str, data: CollectedData, 
                           normalizer: URLNormalizer, domain: str):
        """Extract URLs from robots.txt"""
        try:
            url = f"{base_url}/robots.txt"
            response = await self.rate_limiter.request(self.session, url, timeout=10)
            
            if response and response.status == 200:
                text = await response.text()
                
                for line in text.split('\n'):
                    if line.strip().startswith(('Allow:', 'Disallow:')):
                        path = line.split(':', 1)[1].strip()
                        if path and not path.startswith('#'):
                            full_url = urljoin(base_url, path)
                            normalized = normalizer.normalize_url(full_url)
                            if normalized:
                                data.urls.append(normalized)
                
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
                
                for sitemap_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                    loc = sitemap_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc is not None and loc.text:
                        await self._fetch_sitemap_from_url(loc.text, data, normalizer, domain)
                
                for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                    loc = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc is not None and loc.text:
                        normalized = normalizer.normalize_url(loc.text)
                        if normalized:
                            data.urls.append(normalized)
                            
                            if normalized.endswith('.js'):
                                data.js_files.append(normalized)
            
            except ET.ParseError:
                urls = re.findall(r'<loc>(https?://[^<]+)</loc>', text)
                for url in urls:
                    normalized = normalizer.normalize_url(url)
                    if normalized:
                        data.urls.append(normalized)
        
        except Exception:
            pass
    
    async def _crawl_site(self, base_url: str, data: CollectedData,
                         normalizer: URLNormalizer, domain: str):
        """Crawl the site starting from homepage, visiting multiple internal pages"""
        self.crawl_queue = [base_url]
        html_pages_crawled = 0
        
        while self.crawl_queue and html_pages_crawled < self.max_pages_to_crawl:
            current_batch = []
            while self.crawl_queue and len(current_batch) < 5:
                candidate = self.crawl_queue.pop(0)
                if candidate not in self.visited_pages:
                    current_batch.append(candidate)
                    self.visited_pages.add(candidate)
            
            if not current_batch:
                break
            
            tasks = [
                self._fetch_page_and_extract(page_url, data, normalizer, domain)
                for page_url in current_batch
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, dict):
                    if result.get('is_html'):
                        html_pages_crawled += 1
                    
                    for link in result.get('links', []):
                        if link not in self.visited_pages and link not in self.crawl_queue:
                            if normalizer.is_same_domain(link, domain) and self._is_likely_html_page(link):
                                self.crawl_queue.append(link)
    
    async def _fetch_page_and_extract(self, page_url: str, data: CollectedData,
                                      normalizer: URLNormalizer, domain: str) -> dict:
        """Fetch a page and extract JS files and internal links"""
        result = {'is_html': False, 'links': []}
        
        try:
            response = await self.rate_limiter.request(self.session, page_url, timeout=8)
            
            if not response or response.status != 200:
                return result
            
            content_type = response.headers.get('content-type', '')
            if 'text/html' not in content_type.lower():
                return result
            
            result['is_html'] = True
            html = await response.text()
            
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for script in scripts:
                if script and not script.startswith(('data:', 'javascript:')):
                    full_url = urljoin(page_url, script)
                    normalized = normalizer.normalize_url(full_url)
                    if normalized:
                        data.js_files.append(normalized)
                        data.urls.append(normalized)
            
            hrefs = re.findall(r'href=["\']([^"\'#]+)["\']', html)
            for href in hrefs:
                if href.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
                    continue
                
                full_url = urljoin(page_url, href)
                normalized = normalizer.normalize_url(full_url)
                
                if normalized and normalizer.is_same_domain(full_url, domain):
                    data.urls.append(normalized)
                    
                    if normalized.endswith('.js'):
                        data.js_files.append(normalized)
                    
                    if self._is_likely_html_page(normalized):
                        result['links'].append(normalized)
        
        except Exception:
            pass
        
        return result
