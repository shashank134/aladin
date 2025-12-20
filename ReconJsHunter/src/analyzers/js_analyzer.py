"""
JavaScript static analyzer with enhanced accuracy.
Performs safe static analysis on JavaScript files to extract URLs, secrets, and sensitive data.
Filters out junk data and false positives for accurate results.
"""

import re
import math
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import aiohttp

from src.core.rate_limiter import RateLimiter


@dataclass
class Finding:
    type: str
    value: str
    context: str
    line_number: int
    confidence: str
    description: str
    entropy: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'value': self.value,
            'context': self.context[:200] if self.context else '',
            'line_number': self.line_number,
            'confidence': self.confidence,
            'description': self.description,
            'entropy': round(self.entropy, 2)
        }


@dataclass
class JSAnalysisResult:
    url: str
    size: int = 0
    success: bool = False
    error: Optional[str] = None
    
    urls: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    internal_refs: List[Finding] = field(default_factory=list)
    secrets: List[Finding] = field(default_factory=list)
    sensitive_data: List[Finding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'size': self.size,
            'success': self.success,
            'error': self.error,
            'urls': self.urls,
            'api_endpoints': self.api_endpoints,
            'internal_refs': [f.to_dict() for f in self.internal_refs],
            'secrets': [f.to_dict() for f in self.secrets],
            'sensitive_data': [f.to_dict() for f in self.sensitive_data],
            'stats': {
                'total_urls': len(self.urls),
                'total_endpoints': len(self.api_endpoints),
                'total_internal_refs': len(self.internal_refs),
                'total_secrets': len(self.secrets),
                'total_sensitive': len(self.sensitive_data)
            }
        }


class JSAnalyzer:
    
    SECRET_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'high', 20),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'aws_secret', 'high', 40),
        
        (r'AIza[0-9A-Za-z_-]{35}', 'google_api_key', 'high', 39),
        
        (r'sk_live_[a-zA-Z0-9]{24,}', 'stripe_secret_key', 'high', 32),
        (r'rk_live_[a-zA-Z0-9]{24,}', 'stripe_restricted_key', 'high', 32),
        
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'slack_token', 'high', 50),
        
        (r'ghp_[a-zA-Z0-9]{36}', 'github_pat', 'high', 40),
        (r'gho_[a-zA-Z0-9]{36}', 'github_oauth', 'high', 40),
        (r'ghu_[a-zA-Z0-9]{36}', 'github_user_token', 'high', 40),
        
        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'private_key_pem', 'high', 30),
        
        (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'sendgrid_api_key', 'high', 69),
        
        (r'sk-[a-zA-Z0-9]{48}', 'openai_api_key', 'high', 51),
        
        (r'AC[a-z0-9]{32}', 'twilio_account_sid', 'high', 34),
        
        (r'(?i)(?:mongodb(?:\+srv)?):\/\/[^\s"\'<>]+', 'mongodb_uri', 'high', 30),
        (r'(?i)postgres(?:ql)?:\/\/[^\s"\'<>]+', 'postgres_uri', 'high', 30),
        (r'(?i)mysql:\/\/[^\s"\'<>]+', 'mysql_uri', 'high', 30),
        
        (r'eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}', 'jwt_token', 'medium', 60),
        
        (r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']', 'api_key', 'medium', 32),
        (r'(?i)(?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']', 'secret_key', 'medium', 32),
        (r'(?i)(?:access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{40,})["\']', 'access_token', 'medium', 40),
        (r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{40,})', 'bearer_token', 'medium', 40),
    ]
    
    INTERNAL_PATTERNS = [
        (r'(?<![a-zA-Z0-9])localhost(?::\d+)?(?:/[^\s"\']*)?', 'localhost', 'Localhost reference'),
        (r'(?<![a-zA-Z0-9\.])127\.0\.0\.1(?::\d+)?(?:/[^\s"\']*)?', 'localhost_ip', 'Localhost IP'),
        (r'(?<![a-zA-Z0-9\.])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_10', 'Internal IP (10.x.x.x)'),
        (r'(?<![a-zA-Z0-9\.])172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_172', 'Internal IP (172.16-31.x.x)'),
        (r'(?<![a-zA-Z0-9\.])192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_192', 'Internal IP (192.168.x.x)'),
        (r'https?://[a-z0-9\-]+\.(?:internal|local|dev|test|staging)\b[^\s"\']*', 'internal_domain', 'Internal/Dev domain'),
    ]
    
    SENSITIVE_PATTERNS = [
        (r'(?i)debug\s*[:=]\s*(?:true|1|"true"|\'true\')', 'debug_enabled', 'Debug mode enabled'),
        (r'(?i)admin[_-]?(?:password|pass|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'admin_password', 'Admin password'),
        (r'(?i)(?:webhook[_-]?url|webhookurl)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'webhook_url', 'Webhook URL'),
    ]
    
    JUNK_PATTERNS = [
        r'^[a-f0-9]{32}$',
        r'^[0-9]+$',
        r'^[a-zA-Z]+$',
        r'^(.)\1+$',
        r'^(ab|abc|abcd|test|demo|example|sample|placeholder|changeme|password|secret|key|token|todo|fixme|xxx|yyy|zzz|lorem|ipsum|null|undefined|none|empty|your|enter|insert|replace|default|config|setting).*$',
        r'^[a-zA-Z0-9]{1,15}$',
        r'^.*\$\{.*\}.*$',
        r'^.*\{\{.*\}\}.*$',
        r'^process\.env\.',
        r'^env\.',
        r'^\$[A-Z_]+',
        r'^__[A-Z_]+__$',
    ]
    
    MINIFIED_JS_PATTERNS = [
        r'[a-z]\.[a-z]\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
        r'\b[a-z]{1,2}\s*=\s*["\'][^"\']+["\']',
    ]
    
    COMMON_LIBS = [
        'jquery', 'react', 'angular', 'vue', 'bootstrap', 'lodash', 'moment',
        'axios', 'webpack', 'babel', 'polyfill', 'analytics', 'gtag', 'fbq',
        'maps.google', 'fonts.google', 'cdn.', 'unpkg.com', 'cdnjs.cloudflare',
        'jsdelivr.net', 'cloudflare.com/ajax', 'googletagmanager', 'facebook.net',
        'doubleclick.net', 'googlesyndication', 'google-analytics'
    ]
    
    def __init__(self, max_size: int = 5 * 1024 * 1024, silent_mode: bool = True):
        self.max_size = max_size
        self.silent_mode = silent_mode
        self.rate_limiter = RateLimiter(
            requests_per_second=1.5, 
            max_concurrent=2,
            stealth_mode=True,
            silent_mode=silent_mode
        )
        self.seen_values: Set[str] = set()
    
    async def analyze_urls(self, js_urls: List[str], session: aiohttp.ClientSession) -> List[JSAnalysisResult]:
        results = []
        
        filtered_urls = self._filter_library_urls(js_urls)
        
        for url in filtered_urls[:50]:  # Analyze more files for better coverage
            result = await self.analyze_url(url, session)
            # Return all successful analyses, not just ones with findings
            if result.success:
                results.append(result)
        
        return results
    
    def _filter_library_urls(self, urls: List[str]) -> List[str]:
        filtered = []
        for url in urls:
            url_lower = url.lower()
            is_common_lib = any(lib in url_lower for lib in self.COMMON_LIBS)
            if not is_common_lib:
                filtered.append(url)
        return filtered
    
    async def analyze_url(self, url: str, session: aiohttp.ClientSession) -> JSAnalysisResult:
        result = JSAnalysisResult(url=url)
        
        try:
            response = await self.rate_limiter.request(session, url, timeout=30)
            
            if not response:
                result.error = "Failed to fetch JavaScript file"
                return result
            
            if response.status != 200:
                result.error = f"HTTP {response.status}"
                return result
            
            content = await response.text()
            result.size = len(content)
            
            if result.size > self.max_size:
                result.error = f"File too large ({result.size} bytes)"
                return result
            
            if result.size < 100:
                result.error = "File too small"
                return result
            
            result.urls = self._extract_urls(content, url)
            result.api_endpoints = self._extract_api_endpoints(content)
            result.internal_refs = self._find_internal_refs(content)
            result.secrets = self._find_secrets(content)
            result.sensitive_data = self._find_sensitive_data(content)
            
            result.success = True
            
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _extract_urls(self, content: str, source_url: str) -> List[str]:
        urls = set()
        
        url_pattern = r'https?://[^\s"\'<>\)\]\}\\,;]+[a-zA-Z0-9/]'
        matches = re.findall(url_pattern, content)
        
        for match in matches:
            clean_url = match.rstrip('.,;:')
            if self._is_valid_url(clean_url):
                urls.add(clean_url)
        
        return list(urls)[:200]
    
    def _is_valid_url(self, url: str) -> bool:
        if len(url) < 10 or len(url) > 2000:
            return False
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc or '.' not in parsed.netloc:
                return False
            
            invalid_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.css']
            if any(url.lower().endswith(ext) for ext in invalid_extensions):
                return False
            
            return True
        except:
            return False
    
    def _extract_api_endpoints(self, content: str) -> List[str]:
        endpoints = set()
        
        api_patterns = [
            r'["\']\/api\/v\d+\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/api\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/v\d+\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/graphql["\']',
            r'["\']\/rest\/[a-zA-Z0-9_\-\/]+["\']',
            r'fetch\s*\(\s*[`"\']([^`"\']+\/api\/[^`"\']+)[`"\']',
            r'axios\.[a-z]+\s*\(\s*[`"\']([^`"\']+\/api\/[^`"\']+)[`"\']',
            # Additional patterns for common endpoints
            r'["\']\/admin["\']',
            r'["\']\/user["\']',
            r'["\']\/auth["\']',
            r'["\']\/login["\']',
            r'["\']\/config["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                clean = match.strip('"\'`')
                if clean and len(clean) > 1 and len(clean) < 200:
                    if not any(junk in clean.lower() for junk in ['example', 'placeholder', 'your-']):
                        endpoints.add(clean)
        
        return list(endpoints)[:200]  # Return more endpoints
    
    def _find_internal_refs(self, content: str) -> List[Finding]:
        findings = []
        seen = set()
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            
            for pattern, ref_type, description in self.INTERNAL_PATTERNS:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    value = match.group(0)
                    
                    if value in seen:
                        continue
                    
                    if self._is_in_comment(line, match.start()):
                        continue
                    
                    seen.add(value)
                    findings.append(Finding(
                        type='internal_reference',
                        value=value,
                        context=self._get_clean_context(line, match.start()),
                        line_number=line_num,
                        confidence='medium',
                        description=description
                    ))
        
        return findings[:30]
    
    def _find_secrets(self, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            
            for pattern, secret_type, confidence, min_length in self.SECRET_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    if len(value) < min_length:
                        continue
                    
                    if not self._validate_secret(value, secret_type, line, match.start()):
                        continue
                    
                    value_hash = hash(value)
                    if value_hash in self.seen_values:
                        continue
                    self.seen_values.add(value_hash)
                    
                    entropy = self._calculate_entropy(value)
                    
                    actual_confidence = confidence
                    if entropy < 3.0:
                        actual_confidence = 'low'
                    elif entropy < 4.0 and confidence == 'high':
                        actual_confidence = 'medium'
                    
                    findings.append(Finding(
                        type=secret_type,
                        value=self._mask_secret(value),
                        context=self._get_clean_context(line, match.start()),
                        line_number=line_num,
                        confidence=actual_confidence,
                        description=f"Potential {secret_type.replace('_', ' ')}",
                        entropy=entropy
                    ))
        
        findings.sort(key=lambda x: (
            {'high': 0, 'medium': 1, 'low': 2}.get(x.confidence, 3),
            -x.entropy
        ))
        
        return findings[:50]
    
    def _validate_secret(self, value: str, secret_type: str, line: str, position: int) -> bool:
        if self._is_likely_placeholder(value):
            return False
        
        for junk_pattern in self.JUNK_PATTERNS:
            if re.match(junk_pattern, value, re.IGNORECASE):
                return False
        
        if self._is_in_comment(line, position):
            return False
        
        # Skip minified var check for specific secret types
        if secret_type not in ['jwt_token', 'private_key_pem']:
            if self._is_in_minified_variable(line, position):
                return False
        
        entropy = self._calculate_entropy(value)
        
        # Lower entropy thresholds to catch more real secrets
        if secret_type in ['api_key', 'secret_key', 'access_token', 'bearer_token']:
            if entropy < 2.5:  # Lowered from 3.5
                return False
        
        if secret_type in ['aws_access_key', 'google_api_key', 'stripe_secret_key']:
            if entropy < 2.0:  # Lowered from 3.0
                return False
        
        return True
    
    def _is_in_comment(self, line: str, position: int) -> bool:
        before = line[:position]
        if '//' in before:
            comment_start = before.rfind('//')
            if before[comment_start:].count('"') % 2 == 0 and before[comment_start:].count("'") % 2 == 0:
                return True
        
        if '/*' in before and '*/' not in before[before.rfind('/*'):]:
            return True
        
        return False
    
    def _is_in_minified_variable(self, line: str, position: int) -> bool:
        for pattern in self.MINIFIED_JS_PATTERNS:
            matches = re.finditer(pattern, line)
            for match in matches:
                if match.start() <= position <= match.end():
                    if len(match.group(0)) < 50:
                        return True
        return False
    
    def _find_sensitive_data(self, content: str) -> List[Finding]:
        findings = []
        seen = set()
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            
            for pattern, data_type, description in self.SENSITIVE_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    if value in seen:
                        continue
                    
                    if self._is_in_comment(line, match.start()):
                        continue
                    
                    if self._is_likely_placeholder(value):
                        continue
                    
                    seen.add(value)
                    findings.append(Finding(
                        type=data_type,
                        value=value[:100],
                        context=self._get_clean_context(line, match.start()),
                        line_number=line_num,
                        confidence='medium',
                        description=description
                    ))
        
        return findings[:30]
    
    def _is_likely_placeholder(self, value: str) -> bool:
        placeholders = [
            'xxx', 'yyy', 'zzz', 'your', 'enter', 'insert', 'replace',
            'example', 'sample', 'test', 'demo', 'placeholder', 'changeme',
            'todo', 'fixme', 'undefined', 'null', 'none', 'empty',
            'default', 'config', 'setting', 'password', 'secret', 'key',
            'token', 'api_key', 'apikey', 'lorem', 'ipsum', 'foo', 'bar',
            'baz', 'qux', 'quux', 'dummy', 'mock', 'fake', 'temp', 'tmp'
        ]
        
        lower_value = value.lower()
        
        for placeholder in placeholders:
            if lower_value == placeholder or lower_value.startswith(placeholder + '_') or lower_value.startswith(placeholder + '-'):
                return True
        
        if len(set(value.lower())) <= 3:
            return True
        
        if re.match(r'^(.)\1{5,}$', value):
            return True
        
        if re.match(r'^[a-z]{1,3}$', value, re.IGNORECASE):
            return True
        
        return False
    
    def _mask_secret(self, value: str) -> str:
        if len(value) <= 10:
            return value[:2] + '*' * (len(value) - 2)
        return value[:6] + '*' * (len(value) - 10) + value[-4:]
    
    def _get_clean_context(self, line: str, position: int) -> str:
        line = line.strip()
        start = max(0, position - 40)
        end = min(len(line), position + 60)
        context = line[start:end]
        return context.strip()
    
    def _calculate_entropy(self, value: str) -> float:
        if not value or len(value) < 4:
            return 0.0
        
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = len(value)
        
        for count in freq.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
        
        return entropy
