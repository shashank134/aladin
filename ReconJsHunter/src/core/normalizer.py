"""
URL and domain normalization utilities.
Handles URL cleanup, deduplication, and categorization.
"""

import re
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import List, Set, Tuple, Optional
import tldextract


class URLNormalizer:
    
    def __init__(self):
        self.seen_urls: Set[str] = set()
    
    def normalize_domain(self, domain: str) -> str:
        domain = domain.lower().strip()
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.rstrip('/')
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        
        return domain
    
    def normalize_url(self, url: str, base_domain: str = None) -> Optional[str]:
        url = url.strip()
        
        if not url or url.startswith('#') or url.startswith('javascript:'):
            return None
        
        if url.startswith('data:'):
            return None
        
        if not url.startswith(('http://', 'https://', '//')):
            if base_domain:
                url = urljoin(f'https://{base_domain}', url)
            else:
                url = f'https://{url}'
        
        if url.startswith('//'):
            url = f'https:{url}'
        
        try:
            parsed = urlparse(url)
        except Exception:
            return None
        
        scheme = parsed.scheme.lower() or 'https'
        if scheme not in ('http', 'https'):
            return None
        
        netloc = parsed.netloc.lower()
        if not netloc:
            return None
        
        netloc = re.sub(r'^www\.', '', netloc)
        
        path = parsed.path or '/'
        path = re.sub(r'/+', '/', path)
        
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted(params.items())
            query = urlencode(sorted_params, doseq=True)
        else:
            query = ''
        
        normalized = urlunparse((scheme, netloc, path, '', query, ''))
        
        return normalized
    
    def extract_domain_parts(self, url_or_domain: str) -> Tuple[str, str, str]:
        if '://' in url_or_domain:
            parsed = urlparse(url_or_domain)
            hostname = parsed.netloc
        else:
            hostname = url_or_domain
        
        ext = tldextract.extract(hostname)
        
        subdomain = ext.subdomain
        domain = ext.domain
        suffix = ext.suffix
        
        root_domain = f"{domain}.{suffix}" if suffix else domain
        full_domain = f"{subdomain}.{root_domain}" if subdomain else root_domain
        
        return subdomain, root_domain, full_domain
    
    def is_same_domain(self, url: str, target_domain: str) -> bool:
        _, target_root, _ = self.extract_domain_parts(target_domain)
        _, url_root, _ = self.extract_domain_parts(url)
        
        return target_root.lower() == url_root.lower()
    
    def categorize_url(self, url: str, target_domain: str) -> str:
        if not url:
            return 'invalid'
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        if path.endswith('.js'):
            return 'javascript'
        
        if path.endswith(('.css', '.scss', '.less')):
            return 'stylesheet'
        
        if path.endswith(('.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp')):
            return 'image'
        
        if path.endswith(('.woff', '.woff2', '.ttf', '.eot', '.otf')):
            return 'font'
        
        if not self.is_same_domain(url, target_domain):
            return 'external'
        
        subdomain, root, full = self.extract_domain_parts(url)
        target_subdomain, target_root, _ = self.extract_domain_parts(target_domain)
        
        if subdomain and subdomain != target_subdomain:
            return 'subdomain'
        
        return 'main_domain'
    
    def deduplicate(self, urls: List[str]) -> List[str]:
        seen = set()
        unique = []
        
        for url in urls:
            normalized = self.normalize_url(url)
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
        
        return unique
    
    def is_interesting_endpoint(self, url: str) -> bool:
        interesting_patterns = [
            r'/api/', r'/v\d+/', r'/admin', r'/auth', r'/login',
            r'/signup', r'/register', r'/oauth', r'/token',
            r'/graphql', r'/rest/', r'/webhook', r'/callback',
            r'/debug', r'/test', r'/dev', r'/staging',
            r'/internal', r'/private', r'/secret', r'/hidden',
            r'\.json$', r'\.xml$', r'\.yaml$', r'\.yml$',
            r'/config', r'/settings', r'/env', r'/status',
            r'/health', r'/metrics', r'/info', r'/version'
        ]
        
        path = urlparse(url).path.lower()
        
        for pattern in interesting_patterns:
            if re.search(pattern, path):
                return True
        
        return False


def normalize_input(input_value: str) -> List[str]:
    domains = []
    
    if '\n' in input_value or ',' in input_value:
        items = re.split(r'[,\n]', input_value)
    else:
        items = [input_value]
    
    normalizer = URLNormalizer()
    
    for item in items:
        item = item.strip()
        if item:
            domain = normalizer.normalize_domain(item)
            if domain:
                domains.append(domain)
    
    return list(set(domains))
