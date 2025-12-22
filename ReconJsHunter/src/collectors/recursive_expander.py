"""
Recursive URL expander for discovering additional URLs from fetched pages.
Parses HTML and inline JavaScript to find more URLs and endpoints.
"""

import re
import asyncio
from typing import List, Set, Dict
from urllib.parse import urljoin, urlparse
import aiohttp

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer
from src.core.rate_limiter import RateLimiter


class RecursiveExpander(BaseCollector):
    
    name = "recursive_expander"
    
    MAX_DEPTH = 2
    MAX_URLS_PER_LEVEL = 50
    MAX_TOTAL_URLS = 200
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
        self.normalizer = URLNormalizer()
        self.visited: Set[str] = set()
        self.discovered: Set[str] = set()
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Recursive expansion not run directly - use expand_urls()")
        
        return data
    
    async def expand_urls(self, seed_urls: List[str], domain: str, session: aiohttp.ClientSession) -> CollectedData:
        data = CollectedData(source=self.name)
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Starting recursive expansion from {len(seed_urls)} seed URLs")
        
        self.visited = set()
        self.discovered = set()
        
        current_level = [self.normalizer.normalize_url(url) for url in seed_urls if self.normalizer.normalize_url(url)]
        current_level = [url for url in current_level if self._is_same_domain(url, domain)]
        current_level = list(set(current_level))[:self.MAX_URLS_PER_LEVEL]
        
        for depth in range(self.MAX_DEPTH):
            if not current_level:
                break
            
            if len(self.discovered) >= self.MAX_TOTAL_URLS:
                break
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Depth {depth + 1}: Processing {len(current_level)} URLs")
            
            next_level = []
            
            for url in current_level:
                if url in self.visited:
                    continue
                
                self.visited.add(url)
                
                try:
                    new_urls = await self._fetch_and_extract(url, domain, session)
                    
                    for new_url in new_urls:
                        if new_url not in self.discovered and new_url not in self.visited:
                            self.discovered.add(new_url)
                            data.urls.append(new_url)
                            
                            if new_url.endswith('.js'):
                                data.js_files.append(new_url)
                            
                            subdomain, root, full = self.normalizer.extract_domain_parts(new_url)
                            if subdomain and root.lower() == domain.lower():
                                data.subdomains.add(full)
                            
                            if self.normalizer.is_interesting_endpoint(new_url):
                                data.endpoints.append(new_url)
                            
                            if len(next_level) < self.MAX_URLS_PER_LEVEL:
                                next_level.append(new_url)
                    
                except Exception as e:
                    if not self.silent_mode:
                        logger.debug(f"Error expanding {url}: {e}")
                    continue
                
                if len(self.discovered) >= self.MAX_TOTAL_URLS:
                    break
            
            current_level = next_level
        
        data.deduplicate()
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Discovered {len(data.urls)} new URLs, {len(data.js_files)} JS files")
        
        return data
    
    async def _fetch_and_extract(self, url: str, domain: str, session: aiohttp.ClientSession) -> List[str]:
        urls = []
        
        try:
            timeout = aiohttp.ClientTimeout(total=5, connect=3)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml',
            }
            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
                if response.status != 200:
                    return urls
                
                content_type = response.headers.get('content-type', '').lower()
                if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                    return urls
                
                html = await response.text(errors='replace')
                
                if len(html) > 5 * 1024 * 1024:
                    return urls
                
                urls.extend(self._extract_from_html(html, url, domain))
                urls.extend(self._extract_from_inline_js(html, url, domain))
            
        except Exception:
            pass
        
        return list(set(urls))
    
    def _extract_from_html(self, html: str, base_url: str, domain: str) -> List[str]:
        urls = []
        
        patterns = [
            (r'href=["\']([^"\']+)["\']', 'href'),
            (r'src=["\']([^"\']+)["\']', 'src'),
            (r'action=["\']([^"\']+)["\']', 'action'),
            (r'data-url=["\']([^"\']+)["\']', 'data-url'),
            (r'data-src=["\']([^"\']+)["\']', 'data-src'),
            (r'data-href=["\']([^"\']+)["\']', 'data-href'),
            (r'content=["\']([^"\']*https?://[^"\']+)["\']', 'content'),
        ]
        
        for pattern, attr_name in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                try:
                    full_url = self._resolve_url(match, base_url)
                    if full_url and self._is_valid_discovered_url(full_url, domain):
                        urls.append(full_url)
                except Exception:
                    continue
        
        return urls
    
    def _extract_from_inline_js(self, html: str, base_url: str, domain: str) -> List[str]:
        urls = []
        
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for script in scripts:
            if len(script) > 500000:
                continue
            
            url_patterns = [
                r'["\']/(api|v\d+|graphql|rest|admin|auth|user|config)[^"\']*["\']',
                r'["\']https?://[^"\']+["\']',
                r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']',
                r'axios\.[a-z]+\s*\(\s*[`"\']([^`"\']+)[`"\']',
                r'\.get\s*\(\s*[`"\']([^`"\']+)[`"\']',
                r'\.post\s*\(\s*[`"\']([^`"\']+)[`"\']',
                r'url:\s*[`"\']([^`"\']+)[`"\']',
                r'endpoint:\s*[`"\']([^`"\']+)[`"\']',
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, script, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else match[-1]
                    
                    try:
                        match = match.strip('"\'`')
                        full_url = self._resolve_url(match, base_url)
                        if full_url and self._is_valid_discovered_url(full_url, domain):
                            urls.append(full_url)
                    except Exception:
                        continue
        
        return urls
    
    def _resolve_url(self, url: str, base_url: str) -> str:
        url = url.strip()
        
        if not url or url.startswith('#') or url.startswith('javascript:') or url.startswith('data:'):
            return None
        
        if url.startswith('//'):
            url = 'https:' + url
        elif url.startswith('/'):
            url = urljoin(base_url, url)
        elif not url.startswith('http'):
            url = urljoin(base_url, url)
        
        return self.normalizer.normalize_url(url)
    
    def _is_same_domain(self, url: str, domain: str) -> bool:
        try:
            parsed = urlparse(url)
            return domain.lower() in parsed.netloc.lower()
        except Exception:
            return False
    
    def _is_valid_discovered_url(self, url: str, domain: str) -> bool:
        if not url:
            return False
        
        if not self._is_same_domain(url, domain):
            return False
        
        skip_extensions = [
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
            '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv'
        ]
        
        url_lower = url.lower()
        for ext in skip_extensions:
            if url_lower.endswith(ext):
                return False
        
        if len(url) > 2000:
            return False
        
        return True
