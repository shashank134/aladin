"""
JavaScript URL Filtering Runner - Phase 2 of the modular pipeline.
Extracts and categorizes JavaScript URLs from recon data or user-supplied URL lists.
"""

import re
from typing import Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urlparse

from src.core.normalizer import URLNormalizer
from src.core.logger import logger, set_silent
from src.models import ReconResult, JsFilterResult, JsUrl, JsCategory, DiscoveredUrl, UrlType
from src.services.datastore import DataStore


class JsFilterRunner:
    
    JS_EXTENSION_PATTERN = re.compile(r'\.js(?:\?|#|$)', re.IGNORECASE)
    VERSIONED_JS_PATTERN = re.compile(
        r'(?:'
        r'\.v?\d+(?:\.\d+)*\.js|'  # app.v1.2.3.js or app.1.2.3.js
        r'\.[a-f0-9]{6,32}\.js|'   # app.abc123.js (hash-based)
        r'[-_][a-f0-9]{6,32}\.js|' # app-abc123.js or app_abc123.js
        r'\.min\.js|'              # app.min.js
        r'[-_]v?\d+(?:\.\d+)*\.js' # app-v1.2.3.js or app_1.2.3.js
        r')$',
        re.IGNORECASE
    )
    BUNDLED_JS_PATTERN = re.compile(
        r'(?:'
        r'chunk[.\-_]|'            # chunk.123.js, chunk-abc.js
        r'bundle[.\-_]?|'          # bundle.js, bundle-main.js
        r'vendor[.\-_]?|'          # vendor.js, vendor-chunk.js
        r'main[.\-_]|'             # main.abc123.js
        r'app[.\-_]|'              # app.js, app-bundle.js
        r'runtime[.\-_]|'          # runtime.js
        r'polyfill[.\-_]?|'        # polyfill.js
        r'common[.\-_]|'           # common.js
        r'shared[.\-_]|'           # shared.js
        r'webpack|'                # webpack related
        r'~|'                      # webpack chunk separator
        r'\d+\.[a-f0-9]+\.js$'     # 123.abc456.js (numbered chunks)
        r')',
        re.IGNORECASE
    )
    
    def __init__(self, silent_mode: bool = False, output_dir: str = "recon_output"):
        self.silent_mode = silent_mode
        self.normalizer = URLNormalizer()
        self.datastore = DataStore(output_dir)
        
        if silent_mode:
            set_silent(True)
    
    def _is_js_url(self, url: str) -> bool:
        if not url:
            return False
        parsed = urlparse(url)
        path = parsed.path.lower()
        return bool(self.JS_EXTENSION_PATTERN.search(path))
    
    def _is_versioned(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        return bool(self.VERSIONED_JS_PATTERN.search(path))
    
    def _is_bundled(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        filename = path.split('/')[-1] if '/' in path else path
        return bool(self.BUNDLED_JS_PATTERN.search(filename))
    
    def _categorize_js(self, url: str, target_domain: str) -> JsCategory:
        if self.normalizer.is_same_domain(url, target_domain):
            return JsCategory.INTERNAL
        return JsCategory.EXTERNAL
    
    def _create_js_url(
        self,
        url: str,
        target_domain: str,
        source_url: Optional[str] = None,
        source_domain: Optional[str] = None,
        discovery_method: str = "unknown"
    ) -> JsUrl:
        return JsUrl(
            url=url,
            category=self._categorize_js(url, target_domain),
            source_url=source_url,
            source_domain=source_domain,
            discovery_method=discovery_method,
            is_versioned=self._is_versioned(url),
            is_bundled=self._is_bundled(url),
            metadata={}
        )
    
    def _extract_from_recon_result(self, recon_result: ReconResult, target_domain: str) -> List[JsUrl]:
        js_urls: Dict[str, JsUrl] = {}
        
        for domain, discovered_urls in recon_result.urls_by_domain.items():
            for discovered in discovered_urls:
                if discovered.url_type == UrlType.JAVASCRIPT or self._is_js_url(discovered.url):
                    normalized = self.normalizer.normalize_url(discovered.url, target_domain)
                    if normalized and normalized not in js_urls:
                        js_url = self._create_js_url(
                            url=normalized,
                            target_domain=target_domain,
                            source_url=discovered.url,
                            source_domain=domain,
                            discovery_method=discovered.source
                        )
                        js_urls[normalized] = js_url
        
        return list(js_urls.values())
    
    def _extract_from_url_list(self, urls: List[str], target_domain: str) -> List[JsUrl]:
        js_urls: Dict[str, JsUrl] = {}
        
        for url in urls:
            url = url.strip()
            if not url:
                continue
            
            normalized = self.normalizer.normalize_url(url, target_domain)
            if not normalized:
                continue
            
            if self._is_js_url(normalized):
                if normalized not in js_urls:
                    subdomain, root_domain, _ = self.normalizer.extract_domain_parts(normalized)
                    source_domain = f"{subdomain}.{root_domain}" if subdomain else root_domain
                    
                    js_url = self._create_js_url(
                        url=normalized,
                        target_domain=target_domain,
                        source_url=url,
                        source_domain=source_domain,
                        discovery_method="user_supplied"
                    )
                    js_urls[normalized] = js_url
        
        return list(js_urls.values())
    
    def run(
        self,
        target: str,
        recon_result: Optional[ReconResult] = None,
        url_list_file: Optional[str] = None
    ) -> JsFilterResult:
        target_domain = self.normalizer.normalize_domain(target)
        scan_id = self.datastore.generate_scan_id()
        source_recon_id = recon_result.scan_id if recon_result else None
        
        if not self.silent_mode:
            logger.info(f"Starting JS URL filtering for: {target_domain}")
            logger.info(f"Scan ID: {scan_id}")
        
        all_js_urls: List[JsUrl] = []
        
        if recon_result:
            if not self.silent_mode:
                logger.info("Extracting JS URLs from recon result...")
            all_js_urls.extend(self._extract_from_recon_result(recon_result, target_domain))
        
        if url_list_file:
            if not self.silent_mode:
                logger.info(f"Loading URLs from file: {url_list_file}")
            urls = self.datastore.load_url_list(url_list_file)
            if not self.silent_mode:
                logger.info(f"Loaded {len(urls)} URLs from file")
            all_js_urls.extend(self._extract_from_url_list(urls, target_domain))
        
        if not recon_result and not url_list_file:
            existing_recon = self.datastore.load_recon_result(target_domain)
            if existing_recon:
                if not self.silent_mode:
                    logger.info("Loading existing recon result from datastore...")
                source_recon_id = existing_recon.scan_id
                all_js_urls.extend(self._extract_from_recon_result(existing_recon, target_domain))
            else:
                if not self.silent_mode:
                    logger.warning("No recon result or URL list provided, and no existing recon found")
        
        seen_urls: Set[str] = set()
        deduplicated: List[JsUrl] = []
        for js_url in all_js_urls:
            if js_url.url not in seen_urls:
                seen_urls.add(js_url.url)
                deduplicated.append(js_url)
        
        internal_js = [js for js in deduplicated if js.category == JsCategory.INTERNAL]
        external_js = [js for js in deduplicated if js.category == JsCategory.EXTERNAL]
        
        result = JsFilterResult(
            scan_id=scan_id,
            source_recon_id=source_recon_id,
            filtered_at=datetime.now().isoformat(),
            internal_js=internal_js,
            external_js=external_js,
            total_js_urls=len(deduplicated)
        )
        
        filepath = self.datastore.save_js_filter_result(target_domain, result)
        
        if not self.silent_mode:
            logger.info(f"JS filter results saved to: {filepath}")
            logger.info(f"Total JS URLs: {len(deduplicated)}")
            logger.info(f"Internal JS: {len(internal_js)}")
            logger.info(f"External JS: {len(external_js)}")
            
            versioned_count = sum(1 for js in deduplicated if js.is_versioned)
            bundled_count = sum(1 for js in deduplicated if js.is_bundled)
            logger.info(f"Versioned JS: {versioned_count}")
            logger.info(f"Bundled/Chunked JS: {bundled_count}")
            
            methods = {}
            for js in deduplicated:
                methods[js.discovery_method] = methods.get(js.discovery_method, 0) + 1
            logger.info(f"Discovery methods: {methods}")
        
        return result
    
    def run_from_file(self, target: str, filepath: str) -> JsFilterResult:
        return self.run(target, url_list_file=filepath)
    
    def run_from_recon(self, recon_result: ReconResult) -> JsFilterResult:
        return self.run(recon_result.target, recon_result=recon_result)
