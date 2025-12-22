"""
AlienVault OTX collector.
Uses the OTX API to retrieve threat intelligence data with stealth capabilities.
"""

from typing import List
from urllib.parse import quote

from src.collectors.base import BaseCollector, CollectedData
from src.core.normalizer import URLNormalizer
from src.core.logger import logger


class AlienVaultCollector(BaseCollector):
    
    name = "alienvault"
    
    OTX_API = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, config, silent_mode: bool = True):
        super().__init__(config, silent_mode)
        self.silent_mode = silent_mode
    
    async def collect(self, domain: str) -> CollectedData:
        data = CollectedData(source=self.name)
        normalizer = URLNormalizer()
        
        if not self.is_enabled():
            return data
        
        if not self.silent_mode:
            logger.info(f"[{self.name}] Fetching data from AlienVault OTX...")
        
        try:
            headers = {}
            if self.config.api_key:
                headers['X-OTX-API-KEY'] = self.config.api_key
            
            endpoints_to_check = [
                f"/indicators/domain/{domain}/url_list",
                f"/indicators/domain/{domain}/passive_dns",
            ]
            
            for endpoint in endpoints_to_check:
                await self._fetch_endpoint(endpoint, data, normalizer, domain, headers)
            
            data.deduplicate()
            
            if not self.silent_mode:
                logger.info(f"[{self.name}] Found {len(data.urls)} URLs, {len(data.js_files)} JS files, {len(data.subdomains)} subdomains")
            
        except Exception as e:
            error_msg = f"Error collecting from AlienVault: {e}"
            data.errors.append(error_msg)
            if not self.silent_mode:
                logger.error(error_msg)
        
        return data
    
    async def _fetch_endpoint(self, endpoint: str, data: CollectedData,
                               normalizer: URLNormalizer, domain: str,
                               headers: dict):
        try:
            url = f"{self.OTX_API}{endpoint}"
            
            response = await self.rate_limiter.request(
                self.session, url, headers=headers, timeout=60
            )
            
            if not response or response.status != 200:
                return
            
            result = await response.json()
            
            if 'url_list' in result:
                for entry in result['url_list'][:200]:
                    url_value = entry.get('url', '')
                    if url_value:
                        normalized = normalizer.normalize_url(url_value)
                        if normalized:
                            data.urls.append(normalized)
                            
                            if normalized.endswith('.js'):
                                data.js_files.append(normalized)
                            
                            if normalizer.is_interesting_endpoint(normalized):
                                data.endpoints.append(normalized)
            
            if 'passive_dns' in result:
                for entry in result['passive_dns'][:100]:
                    hostname = entry.get('hostname', '')
                    if hostname and domain in hostname:
                        subdomain, root, full = normalizer.extract_domain_parts(hostname)
                        if subdomain:
                            data.subdomains.add(full)
        
        except Exception:
            pass
