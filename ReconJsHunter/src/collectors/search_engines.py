"""
Search engine collectors for OSINT reconnaissance.
Implements Google, Bing, and DuckDuckGo collectors with anti-blocking measures.
"""

import re
import random
import asyncio
from typing import List, Set
from urllib.parse import quote, urljoin, urlparse

from src.collectors.base import BaseCollector, CollectedData
from src.core.logger import logger
from src.core.normalizer import URLNormalizer
from src.core.rate_limiter import ROTATING_USER_AGENTS


class GoogleCollector(BaseCollector):
    
    name = "google"
    
    SEARCH_URL = "https://www.google.com/search"
    MAX_PAGES = 5
    RESULTS_PER_PAGE = 10
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Searching Google for site:{domain}")
        
        try:
            seen_urls = set()
            
            for page in range(self.MAX_PAGES):
                start = page * self.RESULTS_PER_PAGE
                query = f"site:{domain}"
                
                params = {
                    'q': query,
                    'start': start,
                    'num': self.RESULTS_PER_PAGE,
                    'hl': 'en',
                    'safe': 'off'
                }
                
                query_string = '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
                url = f"{self.SEARCH_URL}?{query_string}"
                
                await asyncio.sleep(random.uniform(2, 5))
                
                try:
                    response = await self.rate_limiter.request(
                        self.session, url, timeout=30
                    )
                    
                    if not response or response.status != 200:
                        if page == 0:
                            data.errors.append(f"Failed to fetch from Google (status: {response.status if response else 'None'})")
                        break
                    
                    html = await response.text()
                    
                    if 'captcha' in html.lower() or 'unusual traffic' in html.lower():
                        data.errors.append("Google CAPTCHA detected - stopping search")
                        break
                    
                    urls_found = self._extract_urls_from_html(html, domain)
                    
                    new_urls = 0
                    for found_url in urls_found:
                        normalized = normalizer.normalize_url(found_url)
                        if normalized and normalized not in seen_urls:
                            seen_urls.add(normalized)
                            new_urls += 1
                            data.urls.append(normalized)
                            
                            if normalized.endswith('.js'):
                                data.js_files.append(normalized)
                            
                            subdomain, root, full = normalizer.extract_domain_parts(normalized)
                            if subdomain and root.lower() == domain.lower():
                                data.subdomains.add(full)
                            
                            if normalizer.is_interesting_endpoint(normalized):
                                data.endpoints.append(normalized)
                    
                    if new_urls == 0:
                        break
                    
                except Exception as e:
                    if not self.silent_mode:
                        logger.debug(f"Google page {page} error: {e}")
                    break
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files, {len(data.subdomains)} subdomains")
            
        except Exception as e:
            error_msg = f"Error collecting from Google: {e}"
            data.errors.append(error_msg)
            if not self.silent_mode:
                logger.error(error_msg)
        
        return data
    
    def _extract_urls_from_html(self, html: str, domain: str) -> List[str]:
        urls = []
        
        patterns = [
            r'href="(/url\?q=|/url\?url=)(https?://[^"&]+)',
            r'href="(https?://[^"]+' + re.escape(domain) + r'[^"]*)"',
            r'cite="(https?://[^"]+)"',
            r'data-href="(https?://[^"]+)"',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    url = match[-1] if match[-1].startswith('http') else match[0]
                else:
                    url = match
                
                if domain.lower() in url.lower():
                    url = url.split('&')[0]
                    urls.append(url)
        
        return urls


class BingCollector(BaseCollector):
    
    name = "bing"
    
    SEARCH_URL = "https://www.bing.com/search"
    MAX_PAGES = 7
    RESULTS_PER_PAGE = 10
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Searching Bing for site:{domain}")
        
        try:
            seen_urls = set()
            
            for page in range(self.MAX_PAGES):
                first = page * self.RESULTS_PER_PAGE + 1
                query = f"site:{domain}"
                
                params = {
                    'q': query,
                    'first': first,
                    'count': self.RESULTS_PER_PAGE,
                }
                
                query_string = '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
                url = f"{self.SEARCH_URL}?{query_string}"
                
                await asyncio.sleep(random.uniform(1.5, 3.5))
                
                try:
                    response = await self.rate_limiter.request(
                        self.session, url, timeout=30
                    )
                    
                    if not response or response.status != 200:
                        if page == 0:
                            data.errors.append(f"Failed to fetch from Bing (status: {response.status if response else 'None'})")
                        break
                    
                    html = await response.text()
                    
                    if 'captcha' in html.lower() or 'verify' in html.lower():
                        data.errors.append("Bing verification detected - stopping search")
                        break
                    
                    urls_found = self._extract_urls_from_html(html, domain)
                    
                    new_urls = 0
                    for found_url in urls_found:
                        normalized = normalizer.normalize_url(found_url)
                        if normalized and normalized not in seen_urls:
                            seen_urls.add(normalized)
                            new_urls += 1
                            data.urls.append(normalized)
                            
                            if normalized.endswith('.js'):
                                data.js_files.append(normalized)
                            
                            subdomain, root, full = normalizer.extract_domain_parts(normalized)
                            if subdomain and root.lower() == domain.lower():
                                data.subdomains.add(full)
                            
                            if normalizer.is_interesting_endpoint(normalized):
                                data.endpoints.append(normalized)
                    
                    if new_urls == 0:
                        break
                    
                except Exception as e:
                    if not self.silent_mode:
                        logger.debug(f"Bing page {page} error: {e}")
                    break
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files, {len(data.subdomains)} subdomains")
            
        except Exception as e:
            error_msg = f"Error collecting from Bing: {e}"
            data.errors.append(error_msg)
            if not self.silent_mode:
                logger.error(error_msg)
        
        return data
    
    def _extract_urls_from_html(self, html: str, domain: str) -> List[str]:
        urls = []
        
        patterns = [
            r'<a[^>]+href="(https?://[^"]+' + re.escape(domain) + r'[^"]*)"',
            r'<cite[^>]*>(https?://[^<]+)</cite>',
            r'<cite[^>]*>([^<]+' + re.escape(domain) + r'[^<]*)</cite>',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for url in matches:
                if domain.lower() in url.lower():
                    if not url.startswith('http'):
                        url = 'https://' + url
                    urls.append(url.split('&')[0])
        
        return urls


class DuckDuckGoCollector(BaseCollector):
    
    name = "duckduckgo"
    
    SEARCH_URL = "https://html.duckduckgo.com/html/"
    MAX_PAGES = 5
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Searching DuckDuckGo for site:{domain}")
        
        try:
            seen_urls = set()
            next_params = None
            
            for page in range(self.MAX_PAGES):
                await asyncio.sleep(random.uniform(2, 4))
                
                try:
                    if page == 0:
                        query = f"site:{domain}"
                        form_data = {
                            'q': query,
                            'b': '',
                            'kl': 'us-en'
                        }
                    elif next_params:
                        form_data = next_params
                    else:
                        break
                    
                    response = await self.rate_limiter.request(
                        self.session,
                        self.SEARCH_URL,
                        timeout=30,
                        method='POST',
                        data=form_data
                    )
                    
                    if not response or response.status != 200:
                        if page == 0:
                            data.errors.append(f"Failed to fetch from DuckDuckGo (status: {response.status if response else 'None'})")
                        break
                    
                    html = await response.text()
                    
                    urls_found = self._extract_urls_from_html(html, domain)
                    next_params = self._extract_next_page_params(html)
                    
                    new_urls = 0
                    for found_url in urls_found:
                        normalized = normalizer.normalize_url(found_url)
                        if normalized and normalized not in seen_urls:
                            seen_urls.add(normalized)
                            new_urls += 1
                            data.urls.append(normalized)
                            
                            if normalized.endswith('.js'):
                                data.js_files.append(normalized)
                            
                            subdomain, root, full = normalizer.extract_domain_parts(normalized)
                            if subdomain and root.lower() == domain.lower():
                                data.subdomains.add(full)
                            
                            if normalizer.is_interesting_endpoint(normalized):
                                data.endpoints.append(normalized)
                    
                    if new_urls == 0 or not next_params:
                        break
                    
                except Exception as e:
                    if not self.silent_mode:
                        logger.debug(f"DuckDuckGo page {page} error: {e}")
                    break
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files, {len(data.subdomains)} subdomains")
            
        except Exception as e:
            error_msg = f"Error collecting from DuckDuckGo: {e}"
            data.errors.append(error_msg)
            if not self.silent_mode:
                logger.error(error_msg)
        
        return data
    
    def _extract_urls_from_html(self, html: str, domain: str) -> List[str]:
        urls = []
        
        patterns = [
            r'class="result__url"[^>]*href="([^"]+)"',
            r'class="result__a"[^>]*href="([^"]+)"',
            r'data-hostname="([^"]+' + re.escape(domain) + r'[^"]*)"',
            r'<a[^>]+class="[^"]*result[^"]*"[^>]+href="(https?://[^"]+)"',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for url in matches:
                if '//' in url and domain.lower() in url.lower():
                    if url.startswith('//'):
                        url = 'https:' + url
                    urls.append(url)
        
        link_pattern = r'href="(https?://[^"]*' + re.escape(domain) + r'[^"]*)"'
        matches = re.findall(link_pattern, html, re.IGNORECASE)
        for url in matches:
            if 'duckduckgo' not in url.lower():
                urls.append(url)
        
        return urls
    
    def _extract_next_page_params(self, html: str) -> dict:
        next_match = re.search(
            r'<input[^>]+name="s"[^>]+value="(\d+)"',
            html
        )
        
        dc_match = re.search(
            r'<input[^>]+name="dc"[^>]+value="(\d+)"',
            html
        )
        
        q_match = re.search(
            r'<input[^>]+name="q"[^>]+value="([^"]+)"',
            html
        )
        
        if next_match and q_match:
            return {
                'q': q_match.group(1),
                's': next_match.group(1),
                'dc': dc_match.group(1) if dc_match else '',
                'nextParams': '',
                'v': 'l',
                'o': 'json',
                'api': '/d.js'
            }
        
        return None
