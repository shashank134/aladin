"""
Rate limiting and request management with stealth capabilities.
Provides async-safe rate limiting with rotating user agents, delays, and anti-detection measures.
"""

import asyncio
import time
import random
from collections import deque
from typing import Optional, List
from dataclasses import dataclass
import aiohttp

ROTATING_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]

REFERER_TEMPLATES = [
    "https://www.google.com/search?q={domain}",
    "https://www.google.com/",
    "https://duckduckgo.com/?q={domain}",
    "https://www.bing.com/search?q={domain}",
    "https://search.yahoo.com/search?p={domain}",
    "",
]

ACCEPT_LANGUAGE_OPTIONS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.8",
    "en;q=0.9",
]


@dataclass
class RateLimitState:
    requests: deque
    lock: asyncio.Lock
    

class RateLimiter:
    
    def __init__(self, requests_per_second: float = 1.5, 
                 max_concurrent: int = 3,
                 retry_attempts: int = 5,
                 retry_delay: float = 3.0,
                 stealth_mode: bool = True,
                 silent_mode: bool = True):
        self.requests_per_second = requests_per_second
        self.max_concurrent = max_concurrent
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.stealth_mode = stealth_mode
        self.silent_mode = silent_mode
        
        self.request_times: deque = deque(maxlen=100)
        self.lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        self.total_requests = 0
        self.blocked_requests = 0
        self.failed_requests = 0
        self.successful_requests = 0
        
        self.min_delay = 0.5
        self.max_delay = 2.0
        self.backoff_multiplier = 1.5
        self.current_backoff = 1.0
    
    def _get_random_user_agent(self) -> str:
        return random.choice(ROTATING_USER_AGENTS)
    
    def _get_random_referer(self, domain: str = "") -> str:
        template = random.choice(REFERER_TEMPLATES)
        if "{domain}" in template:
            return template.format(domain=domain)
        return template
    
    def _get_random_accept_language(self) -> str:
        return random.choice(ACCEPT_LANGUAGE_OPTIONS)
    
    def _build_stealth_headers(self, original_headers: dict = None, url: str = "") -> dict:
        headers = original_headers.copy() if original_headers else {}
        
        if self.stealth_mode:
            from urllib.parse import urlparse
            parsed = urlparse(url) if url else None
            domain = parsed.netloc if parsed else ""
            
            headers.update({
                'User-Agent': self._get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': self._get_random_accept_language(),
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'cross-site',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0',
                'DNT': '1',
            })
            
            referer = self._get_random_referer(domain)
            if referer:
                headers['Referer'] = referer
        
        return headers
    
    async def _add_random_delay(self):
        if self.stealth_mode:
            delay = random.uniform(self.min_delay, self.max_delay) * self.current_backoff
            await asyncio.sleep(delay)
    
    async def acquire(self):
        async with self.lock:
            now = time.time()
            
            while self.request_times and now - self.request_times[0] > 1.0:
                self.request_times.popleft()
            
            if len(self.request_times) >= self.requests_per_second:
                oldest = self.request_times[0]
                sleep_time = 1.0 - (now - oldest)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
            
            self.request_times.append(time.time())
            self.total_requests += 1
    
    async def request(self, session: aiohttp.ClientSession, url: str,
                      headers: dict = None, timeout: int = 45,
                      method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        async with self.semaphore:
            for attempt in range(self.retry_attempts):
                try:
                    await self.acquire()
                    await self._add_random_delay()
                    
                    stealth_headers = self._build_stealth_headers(headers, url)
                    
                    async with session.request(
                        method, url,
                        headers=stealth_headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                        **kwargs
                    ) as response:
                        
                        if response.status == 429:
                            self.blocked_requests += 1
                            retry_after = int(response.headers.get('Retry-After', self.retry_delay * (attempt + 2)))
                            retry_after = min(retry_after, 60)
                            self.current_backoff = min(self.current_backoff * self.backoff_multiplier, 5.0)
                            await asyncio.sleep(retry_after + random.uniform(1, 3))
                            continue
                        
                        if response.status == 403:
                            self.blocked_requests += 1
                            await asyncio.sleep(random.uniform(3, 8))
                            continue
                        
                        if response.status >= 500:
                            await asyncio.sleep(self.retry_delay * (attempt + 1) + random.uniform(1, 3))
                            continue
                        
                        content = await response.read()
                        
                        self.successful_requests += 1
                        self.current_backoff = max(1.0, self.current_backoff * 0.9)
                        
                        class ResponseWrapper:
                            def __init__(self, status, resp_headers, content, url):
                                self.status = status
                                self.headers = resp_headers
                                self.content = content
                                self.url = url
                            
                            async def text(self):
                                return self.content.decode('utf-8', errors='replace')
                            
                            async def json(self):
                                import json
                                return json.loads(self.content)
                        
                        return ResponseWrapper(response.status, response.headers, content, str(response.url))
                
                except asyncio.TimeoutError:
                    await asyncio.sleep(self.retry_delay + random.uniform(0.5, 2))
                
                except aiohttp.ClientError:
                    await asyncio.sleep(self.retry_delay + random.uniform(0.5, 2))
                
                except Exception:
                    self.failed_requests += 1
                    return None
            
            self.failed_requests += 1
            return None
    
    def get_stats(self) -> dict:
        return {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'blocked_requests': self.blocked_requests,
            'failed_requests': self.failed_requests,
            'success_rate': (self.successful_requests) / max(1, self.total_requests) * 100,
            'current_backoff': self.current_backoff
        }
