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
import asyncio

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


@dataclass
class DownloadStats:
    total: int = 0
    success: int = 0
    failed: int = 0
    timeout: int = 0
    decode_error: int = 0
    http_error: int = 0
    too_large: int = 0
    too_small: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'total': self.total,
            'success': self.success,
            'failed': self.failed,
            'timeout': self.timeout,
            'decode_error': self.decode_error,
            'http_error': self.http_error,
            'too_large': self.too_large,
            'too_small': self.too_small,
            'success_rate': f"{(self.success / self.total * 100) if self.total > 0 else 0:.1f}%"
        }


class JSAnalyzer:
    
    SECRET_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'high', 20),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'aws_secret', 'high', 40),
        (r'(?i)AWS_ACCESS_KEY_ID["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'aws_access_key_id', 'high', 20),
        (r'(?i)AWS_SECRET_ACCESS_KEY["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'aws_secret_access_key', 'high', 40),
        (r'(?i)aws[_-]?session[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{100,})["\']', 'aws_session_token', 'high', 100),
        (r'(?i)s3\.amazonaws\.com/[a-zA-Z0-9\-_.]+', 's3_bucket_url', 'medium', 15),
        (r'(?i)[a-zA-Z0-9\-_.]+\.s3\.amazonaws\.com', 's3_bucket_subdomain', 'medium', 15),
        (r'(?i)[a-zA-Z0-9\-_.]+\.s3\.[a-z0-9\-]+\.amazonaws\.com', 's3_bucket_regional', 'medium', 15),
        
        (r'AIza[0-9A-Za-z_-]{35}', 'google_api_key', 'high', 39),
        (r'(?i)"type"\s*:\s*"service_account"', 'gcp_service_account', 'high', 10),
        (r'(?i)client_email["\']?\s*:\s*["\'][a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com["\']', 'gcp_service_account_email', 'high', 30),
        (r'(?i)private_key["\']?\s*:\s*["\']-----BEGIN', 'gcp_private_key', 'high', 20),
        (r'ya29\.[0-9A-Za-z_-]{50,}', 'google_oauth_token', 'high', 50),
        
        (r'(?i)AccountKey\s*=\s*([a-zA-Z0-9/+=]{86,88})', 'azure_storage_key', 'high', 86),
        (r'(?i)SharedAccessSignature\s*=\s*([a-zA-Z0-9%=&]+)', 'azure_sas_token', 'high', 30),
        (r'(?i)DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+', 'azure_connection_string', 'high', 40),
        (r'(?i)azure[_-]?(?:storage[_-]?)?(?:account[_-]?)?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{86,88})["\']', 'azure_key', 'high', 86),
        (r'(?i)azure[_-]?(?:client[_-]?)?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.~]{34,})["\']', 'azure_client_secret', 'high', 34),
        
        (r'sk_live_[a-zA-Z0-9]{24,}', 'stripe_secret_key_live', 'high', 32),
        (r'rk_live_[a-zA-Z0-9]{24,}', 'stripe_restricted_key_live', 'high', 32),
        (r'pk_live_[a-zA-Z0-9]{24,}', 'stripe_public_key_live', 'medium', 32),
        (r'sk_test_[a-zA-Z0-9]{24,}', 'stripe_secret_key_test', 'medium', 32),
        (r'rk_test_[a-zA-Z0-9]{24,}', 'stripe_restricted_key_test', 'low', 32),
        (r'pk_test_[a-zA-Z0-9]{24,}', 'stripe_public_key_test', 'low', 32),
        (r'(?i)stripe[_-]?(?:api[_-]?)?(?:secret[_-]?)?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_]{24,})["\']', 'stripe_key', 'high', 24),
        
        (r'(?i)PAYPAL_CLIENT_ID["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']', 'paypal_client_id', 'high', 20),
        (r'(?i)PAYPAL_SECRET["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']', 'paypal_secret', 'high', 20),
        (r'(?i)paypal[_-]?(?:client[_-]?)?(?:id|secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-]{32,80})["\']', 'paypal_credential', 'high', 32),
        (r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', 'paypal_braintree_token', 'high', 50),
        
        (r'AC[a-f0-9]{32}', 'twilio_account_sid', 'high', 34),
        (r'SK[a-f0-9]{32}', 'twilio_api_key', 'high', 34),
        (r'(?i)TWILIO_AUTH_TOKEN["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'twilio_auth_token', 'high', 32),
        (r'(?i)TWILIO_ACCOUNT_SID["\']?\s*[:=]\s*["\']([A-Za-z0-9]{34})["\']', 'twilio_account_sid_env', 'high', 34),
        (r'(?i)twilio[_-]?(?:api[_-]?)?(?:key|secret|token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\']', 'twilio_credential', 'high', 32),
        
        (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'sendgrid_api_key', 'high', 69),
        (r'(?i)SENDGRID_API_KEY["\']?\s*[:=]\s*["\']([a-zA-Z0-9._-]{50,70})["\']', 'sendgrid_api_key_env', 'high', 50),
        
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'slack_token', 'high', 50),
        (r'xox[baprs]-[0-9A-Za-z\-]{50,}', 'slack_token_new', 'high', 50),
        (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9]+', 'slack_webhook', 'high', 70),
        (r'(?i)SLACK_(?:BOT_)?TOKEN["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-]{50,})["\']', 'slack_token_env', 'high', 50),
        (r'(?i)SLACK_WEBHOOK[_-]?URL["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'slack_webhook_env', 'high', 30),
        
        (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+', 'discord_webhook', 'high', 60),
        (r'(?i)discord[_-]?(?:bot[_-]?)?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9._-]{50,70})["\']', 'discord_bot_token', 'high', 50),
        (r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}', 'discord_token_format', 'high', 50),
        
        (r'ghp_[a-zA-Z0-9]{36}', 'github_pat', 'high', 40),
        (r'gho_[a-zA-Z0-9]{36}', 'github_oauth', 'high', 40),
        (r'ghu_[a-zA-Z0-9]{36}', 'github_user_token', 'high', 40),
        (r'ghs_[a-zA-Z0-9]{36}', 'github_server_token', 'high', 40),
        (r'ghr_[a-zA-Z0-9]{36}', 'github_refresh_token', 'high', 40),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'github_fine_grained_pat', 'high', 80),
        (r'(?i)GITHUB_TOKEN["\']?\s*[:=]\s*["\']([a-zA-Z0-9_]{36,})["\']', 'github_token_env', 'high', 36),
        
        (r'glpat-[a-zA-Z0-9_\-]{20,}', 'gitlab_pat', 'high', 26),
        (r'glptt-[a-zA-Z0-9_\-]{40,}', 'gitlab_pipeline_trigger', 'high', 46),
        (r'GR1348941[a-zA-Z0-9_\-]{20,}', 'gitlab_runner_token', 'high', 30),
        (r'(?i)GITLAB_(?:ACCESS_)?TOKEN["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'gitlab_token_env', 'high', 20),
        
        (r'(?i)firebase[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{35,45})["\']', 'firebase_api_key', 'high', 35),
        (r'(?i)firebase[a-zA-Z0-9\-]+\.firebaseio\.com', 'firebase_database_url', 'medium', 20),
        (r'(?i)firebase[a-zA-Z0-9\-]+\.appspot\.com', 'firebase_storage_url', 'medium', 20),
        (r'(?i)FIREBASE_(?:API_)?KEY["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{35,45})["\']', 'firebase_key_env', 'high', 35),
        (r'(?i)"apiKey"\s*:\s*"AIza[0-9A-Za-z_-]{35}"', 'firebase_config_key', 'high', 39),
        
        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'private_key_pem', 'high', 30),
        (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'pgp_private_key', 'high', 30),
        (r'-----BEGIN CERTIFICATE-----', 'certificate', 'medium', 25),
        
        (r'sk-[a-zA-Z0-9]{48}', 'openai_api_key', 'high', 51),
        (r'sk-proj-[a-zA-Z0-9_-]{20,}', 'openai_project_key', 'high', 30),
        (r'(?i)OPENAI_API_KEY["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{48,})["\']', 'openai_key_env', 'high', 48),
        
        (r'(?i)(?:mongodb(?:\+srv)?):\/\/[^\s"\'<>]+', 'mongodb_uri', 'high', 30),
        (r'(?i)postgres(?:ql)?:\/\/[^\s"\'<>]+', 'postgres_uri', 'high', 30),
        (r'(?i)mysql:\/\/[^\s"\'<>]+', 'mysql_uri', 'high', 30),
        (r'(?i)redis:\/\/[^\s"\'<>]+', 'redis_uri', 'high', 20),
        (r'(?i)amqp:\/\/[^\s"\'<>]+', 'rabbitmq_uri', 'high', 20),
        (r'(?i)mssql:\/\/[^\s"\'<>]+', 'mssql_uri', 'high', 20),
        (r'(?i)oracle:\/\/[^\s"\'<>]+', 'oracle_uri', 'high', 20),
        (r'(?i)(?:jdbc:)?mariadb:\/\/[^\s"\'<>]+', 'mariadb_uri', 'high', 20),
        
        (r'(?i)mailgun[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-]{32,36})["\']', 'mailgun_api_key', 'high', 32),
        (r'key-[a-f0-9]{32}', 'mailgun_key', 'high', 36),
        
        (r'(?i)mailchimp[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([a-f0-9]{32}-us\d+)["\']', 'mailchimp_api_key', 'high', 36),
        
        (r'(?i)heroku[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([a-f0-9\-]{36})["\']', 'heroku_api_key', 'high', 36),
        
        (r'sq0atp-[a-zA-Z0-9_\-]{22}', 'square_access_token', 'high', 29),
        (r'sq0csp-[a-zA-Z0-9_\-]{43}', 'square_oauth_secret', 'high', 50),
        
        (r'(?i)shopify[_-]?(?:api[_-]?)?(?:key|secret|token)["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'shopify_key', 'high', 32),
        (r'shpat_[a-fA-F0-9]{32}', 'shopify_access_token', 'high', 38),
        (r'shpss_[a-fA-F0-9]{32}', 'shopify_shared_secret', 'high', 38),
        (r'shppa_[a-fA-F0-9]{32}', 'shopify_partner_token', 'high', 38),
        
        (r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@sentry\.io', 'sentry_dsn', 'medium', 30),
        
        (r'(?i)algolia[_-]?(?:api[_-]?)?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{32})["\']', 'algolia_api_key', 'high', 32),
        
        (r'(?i)cloudinary:\/\/[0-9]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9_\-]+', 'cloudinary_url', 'high', 40),
        
        (r'(?i)npm[_-]?(?:auth[_-]?)?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-]{36})["\']', 'npm_token', 'high', 36),
        (r'npm_[a-zA-Z0-9]{36}', 'npm_token_new', 'high', 40),
        
        (r'(?i)nuget[_-]?(?:api[_-]?)?key["\']?\s*[:=]\s*["\']([a-z0-9]{46})["\']', 'nuget_api_key', 'high', 46),
        
        (r'(?i)artifactory[_-]?(?:api[_-]?)?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{73})["\']', 'artifactory_api_key', 'high', 73),
        
        (r'eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}', 'jwt_token', 'medium', 60),
        
        (r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})', 'bearer_token', 'medium', 20),
        (r'(?i)Authorization["\']?\s*[:=]\s*["\']Bearer\s+([a-zA-Z0-9_\-\.]{20,})["\']', 'bearer_auth_header', 'high', 20),
        
        (r'(?i)Basic\s+([a-zA-Z0-9+/=]{20,})', 'basic_auth', 'medium', 20),
        (r'(?i)Authorization["\']?\s*[:=]\s*["\']Basic\s+([a-zA-Z0-9+/=]{20,})["\']', 'basic_auth_header', 'high', 20),
        
        (r'(?i)datadog[_-]?(?:api[_-]?)?key["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'datadog_api_key', 'high', 32),
        (r'(?i)DD_API_KEY["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'datadog_api_key_env', 'high', 32),
        
        (r'(?i)new[_-]?relic[_-]?(?:license[_-]?)?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{40})["\']', 'newrelic_key', 'high', 40),
        (r'NRAK-[A-Z0-9]{27}', 'newrelic_api_key', 'high', 32),
        
        (r'(?i)mapbox[_-]?(?:access[_-]?)?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9._\-]{80,90})["\']', 'mapbox_token', 'medium', 80),
        (r'pk\.eyJ[a-zA-Z0-9_\-]{50,}', 'mapbox_public_token', 'low', 50),
        (r'sk\.eyJ[a-zA-Z0-9_\-]{50,}', 'mapbox_secret_token', 'high', 50),
        
        (r'(?i)digitalocean[_-]?(?:access[_-]?)?token["\']?\s*[:=]\s*["\']([a-f0-9]{64})["\']', 'digitalocean_token', 'high', 64),
        (r'dop_v1_[a-f0-9]{64}', 'digitalocean_pat', 'high', 70),
        
        (r'(?i)circleci[_-]?token["\']?\s*[:=]\s*["\']([a-f0-9]{40})["\']', 'circleci_token', 'high', 40),
        
        (r'(?i)travis[_-]?(?:api[_-]?)?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'travis_token', 'high', 20),
        
        (r'(?i)jenkins[_-]?(?:api[_-]?)?token["\']?\s*[:=]\s*["\']([a-f0-9]{32,34})["\']', 'jenkins_token', 'high', 32),
        
        (r'(?i)sonarqube[_-]?token["\']?\s*[:=]\s*["\']([a-z0-9]{40})["\']', 'sonarqube_token', 'high', 40),
        (r'sqp_[a-f0-9]{40}', 'sonarqube_token_format', 'high', 44),
        
        (r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']', 'api_key', 'medium', 32),
        (r'(?i)(?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']', 'secret_key', 'medium', 32),
        (r'(?i)(?:access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{40,})["\']', 'access_token', 'medium', 40),
        (r'(?i)(?:auth[_-]?token|authtoken)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{32,})["\']', 'auth_token', 'medium', 32),
        (r'(?i)(?:private[_-]?key|privatekey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{40,})["\']', 'private_key', 'medium', 40),
        (r'(?i)(?:encryption[_-]?key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{16,})["\']', 'encryption_key', 'medium', 16),
        (r'(?i)(?:client[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'client_secret', 'medium', 20),
        (r'(?i)(?:app[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'app_secret', 'medium', 20),
        (r'(?i)(?:session[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'session_secret', 'medium', 16),
        (r'(?i)(?:signing[_-]?secret|signature[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'signing_secret', 'medium', 16),
        (r'(?i)(?:webhook[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'webhook_secret', 'medium', 16),
        (r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'hardcoded_password', 'high', 8),
        (r'(?i)pwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'hardcoded_password_short', 'medium', 8),
    ]
    
    INTERNAL_PATTERNS = [
        (r'(?<![a-zA-Z0-9])localhost(?::\d+)?(?:/[^\s"\']*)?', 'localhost', 'Localhost reference'),
        (r'(?<![a-zA-Z0-9\.])127\.0\.0\.1(?::\d+)?(?:/[^\s"\']*)?', 'localhost_ip', 'Localhost IP'),
        (r'(?<![a-zA-Z0-9\.])0\.0\.0\.0(?::\d+)?', 'bind_all_ip', 'Bind all interfaces (0.0.0.0)'),
        (r'(?<![a-zA-Z0-9\.])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_10', 'Internal IP (10.x.x.x)'),
        (r'(?<![a-zA-Z0-9\.])172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_172', 'Internal IP (172.16-31.x.x)'),
        (r'(?<![a-zA-Z0-9\.])192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_192', 'Internal IP (192.168.x.x)'),
        (r'https?://[a-z0-9\-]+\.internal(?:\.[a-z]+)?(?::\d+)?[^\s"\']*', 'internal_domain', 'Internal domain (.internal)'),
        (r'https?://[a-z0-9\-]+\.local(?:host)?(?:\.[a-z]+)?(?::\d+)?[^\s"\']*', 'local_domain', 'Local domain (.local)'),
        (r'https?://[a-z0-9\-]+\.dev(?:\.[a-z]+)?(?::\d+)?[^\s"\']*', 'dev_domain', 'Development domain (.dev)'),
        (r'https?://[a-z0-9\-]+\.test(?:\.[a-z]+)?(?::\d+)?[^\s"\']*', 'test_domain', 'Test domain (.test)'),
        (r'https?://[a-z0-9\-]+\.staging(?:\.[a-z]+)?(?::\d+)?[^\s"\']*', 'staging_domain', 'Staging domain (.staging)'),
        (r'https?://(?:dev|test|staging|qa|uat)[a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]+[^\s"\']*', 'env_subdomain', 'Environment subdomain'),
        (r'https?://[a-z0-9\-]+\.corp(?:\.[a-z]+)?[^\s"\']*', 'corp_domain', 'Corporate domain (.corp)'),
        (r'https?://[a-z0-9\-]+\.intra(?:net)?(?:\.[a-z]+)?[^\s"\']*', 'intranet_domain', 'Intranet domain'),
    ]
    
    SENSITIVE_PATTERNS = [
        (r'(?i)debug\s*[:=]\s*(?:true|1|"true"|\'true\')', 'debug_enabled', 'Debug mode enabled'),
        (r'(?i)DEBUG\s*[:=]\s*(?:true|1|"true"|\'true\')', 'DEBUG_enabled', 'DEBUG flag enabled'),
        (r'(?i)admin[_-]?(?:password|pass|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'admin_password', 'Admin password'),
        (r'(?i)(?:webhook[_-]?url|webhookurl)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'webhook_url', 'Webhook URL'),
        (r'(?i)(?:dev[_-]?mode|development[_-]?mode)\s*[:=]\s*(?:true|1|"true"|\'true\')', 'dev_mode', 'Development mode enabled'),
        (r'(?i)(?:test[_-]?mode|testing)\s*[:=]\s*(?:true|1|"true"|\'true\')', 'test_mode', 'Test mode enabled'),
        (r'(?i)(?:staging|stage)\s*[:=]\s*(?:true|1|"true"|\'true\')', 'staging_mode', 'Staging mode enabled'),
        (r'(?i)enable[_-]?(?:debug|logging)\s*[:=]\s*(?:true|1)', 'debug_logging', 'Debug logging enabled'),
        (r'(?i)verbose\s*[:=]\s*(?:true|1|"true"|\'true\')', 'verbose_mode', 'Verbose mode enabled'),
        (r'(?i)(?:feature[_-]?flag|ff)["\']?\s*[:=]\s*\{[^}]+\}', 'feature_flags', 'Feature flags configuration'),
        (r'(?i)(?:flag|feature)["\']?\s*:\s*\{[^}]*enabled[^}]*\}', 'feature_flag_enabled', 'Feature flag config'),
        (r'(?i)FEATURE_[A-Z_]+\s*[:=]\s*(?:true|false|1|0|"[^"]*"|\'[^\']*\')', 'feature_flag_var', 'Feature flag variable'),
        (r'(?i)FLAG_[A-Z_]+\s*[:=]\s*(?:true|false|1|0|"[^"]*"|\'[^\']*\')', 'flag_var', 'Flag variable'),
        (r'(?i)ENABLE_[A-Z_]+\s*[:=]\s*(?:true|false|1|0)', 'enable_flag', 'Enable flag'),
        (r'(?i)DISABLE_[A-Z_]+\s*[:=]\s*(?:true|false|1|0)', 'disable_flag', 'Disable flag'),
        (r'(?i)(?:internal[_-]?api|admin[_-]?api)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'internal_api', 'Internal API endpoint'),
        (r'(?i)(?:bypass|skip)[_-]?(?:auth|authentication)\s*[:=]\s*(?:true|1)', 'auth_bypass', 'Authentication bypass'),
        (r'(?i)(?:disable[_-]?)?(?:csrf|xss)[_-]?(?:protection|check)?\s*[:=]\s*(?:false|0)', 'security_disabled', 'Security protection disabled'),
        (r'(?i)(?:admin|root)[_-]?(?:user|username)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'admin_username', 'Admin username exposed'),
        (r'(?i)(?:default|initial)[_-]?password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', 'default_password', 'Default password'),
        (r'(?i)environment["\']?\s*[:=]\s*["\'](?:development|staging|dev|test)["\']', 'environment_config', 'Non-production environment'),
        (r'(?i)(?:node[_-]?)?env["\']?\s*[:=]\s*["\'](?:development|dev|test)["\']', 'node_env', 'Development Node environment'),
        (r'(?i)NODE_ENV["\']?\s*[:=]\s*["\'](?:development|dev|test)["\']', 'NODE_ENV', 'NODE_ENV development'),
        (r'(?i)(?:log[_-]?)?level["\']?\s*[:=]\s*["\'](?:debug|trace|verbose)["\']', 'log_level', 'Debug log level'),
        (r'(?i)(?:ssl|tls)[_-]?verify\s*[:=]\s*(?:false|0)', 'ssl_verify_disabled', 'SSL verification disabled'),
        (r'(?i)allow[_-]?cors[_-]?origin\s*[:=]\s*["\']?\*["\']?', 'cors_wildcard', 'CORS allows all origins'),
        (r'(?i)(?:backup|dump)[_-]?(?:url|path)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'backup_location', 'Backup location exposed'),
        (r'(?i)(?:upload|file)[_-]?(?:path|dir)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'upload_path', 'Upload path exposed'),
        (r'(?i)insecure[_-]?(?:mode|skip[_-]?verify)\s*[:=]\s*(?:true|1)', 'insecure_mode', 'Insecure mode enabled'),
        (r'(?i)allow[_-]?(?:insecure|unsafe)\s*[:=]\s*(?:true|1)', 'allow_insecure', 'Allow insecure enabled'),
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
            requests_per_second=3.0,
            max_concurrent=5,
            stealth_mode=True,
            silent_mode=silent_mode
        )
        self.seen_values: Set[str] = set()
        self.download_stats = DownloadStats()
    
    async def analyze_urls(self, js_urls: List[str], session: aiohttp.ClientSession) -> List[JSAnalysisResult]:
        results = []
        
        filtered_urls = self._filter_library_urls(js_urls)
        
        self.download_stats = DownloadStats()
        
        for url in filtered_urls[:100]:
            self.download_stats.total += 1
            result = await self.analyze_url(url, session)
            if result.success:
                self.download_stats.success += 1
                results.append(result)
            else:
                self.download_stats.failed += 1
        
        if not self.silent_mode:
            print(f"Download stats: {self.download_stats.to_dict()}")
        
        return results
    
    def _filter_library_urls(self, urls: List[str]) -> List[str]:
        filtered = []
        for url in urls:
            url_lower = url.lower()
            is_common_lib = any(lib in url_lower for lib in self.COMMON_LIBS)
            if not is_common_lib:
                filtered.append(url)
        return filtered
    
    def _extract_live_url(self, archive_url: str) -> Optional[str]:
        """Extract the original live URL from an archive.org URL.
        
        Archive formats:
        - https://web.archive.org/web/{timestamp}id_/{original_url}
        - https://web.archive.org/web/{timestamp}/{original_url}
        """
        match = re.search(r'web\.archive\.org/web/\d+(?:id_)?/(https?://.+)', archive_url)
        if match:
            return match.group(1)
        return None
    
    async def analyze_url(self, url: str, session: aiohttp.ClientSession) -> JSAnalysisResult:
        result = JSAnalysisResult(url=url)
        
        try:
            try:
                response = await self.rate_limiter.request(session, url, timeout=10)
            except asyncio.TimeoutError:
                self.download_stats.timeout += 1
                result.error = "Timeout (10s)"
                return result
            except Exception as e:
                result.error = f"Request failed: {str(e)[:100]}"
                return result
            
            if not response:
                result.error = "Failed to fetch JavaScript file"
                return result
            
            if response.status != 200:
                if 'web.archive.org' in url:
                    live_url = self._extract_live_url(url)
                    if live_url:
                        try:
                            response = await self.rate_limiter.request(session, live_url, timeout=10)
                            if response and response.status == 200:
                                if not self.silent_mode:
                                    print(f"  Fallback to live URL succeeded: {live_url[:80]}")
                            else:
                                self.download_stats.http_error += 1
                                result.error = f"HTTP {response.status if response else 'no response'} (archive and live failed)"
                                return result
                        except Exception as e:
                            self.download_stats.http_error += 1
                            result.error = f"HTTP error (archive 404, live failed: {str(e)[:50]})"
                            return result
                    else:
                        self.download_stats.http_error += 1
                        result.error = f"HTTP {response.status}"
                        return result
                else:
                    self.download_stats.http_error += 1
                    result.error = f"HTTP {response.status}"
                    return result
            
            try:
                content = await response.text(errors='replace')
            except UnicodeDecodeError:
                self.download_stats.decode_error += 1
                try:
                    raw_bytes = await response.read()
                    content = raw_bytes.decode('utf-8', errors='replace')
                except Exception:
                    result.error = "Decode error"
                    return result
            except Exception as e:
                self.download_stats.decode_error += 1
                result.error = f"Read error: {str(e)[:50]}"
                return result
            
            result.size = len(content)
            
            if result.size > self.max_size:
                self.download_stats.too_large += 1
                result.error = f"File too large ({result.size} bytes)"
                return result
            
            if result.size < 100:
                self.download_stats.too_small += 1
                result.error = "File too small"
                return result
            
            result.urls = self._extract_urls(content, url)
            result.api_endpoints = self._extract_api_endpoints(content)
            result.internal_refs = self._find_internal_refs(content)
            result.secrets = self._find_secrets(content)
            result.sensitive_data = self._find_sensitive_data(content)
            
            high_entropy_findings = self.detect_high_entropy_strings(content)
            for finding in high_entropy_findings:
                if not any(s.value == finding.value for s in result.secrets):
                    result.secrets.append(finding)
            
            result.success = True
            
        except asyncio.TimeoutError:
            self.download_stats.timeout += 1
            result.error = "Timeout"
        except asyncio.CancelledError:
            result.error = "Cancelled"
        except Exception as e:
            result.error = str(e)[:100]
        
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
            r'["\']\/admin["\']',
            r'["\']\/admin\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/user["\']',
            r'["\']\/users\/[a-zA-Z0-9_\-\/]*["\']',
            r'["\']\/auth["\']',
            r'["\']\/auth\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/login["\']',
            r'["\']\/logout["\']',
            r'["\']\/signup["\']',
            r'["\']\/register["\']',
            r'["\']\/config["\']',
            r'["\']\/settings["\']',
            r'["\']\/oauth[a-zA-Z0-9_\-\/]*["\']',
            r'["\']\/token["\']',
            r'["\']\/tokens\/[a-zA-Z0-9_\-\/]*["\']',
            r'["\']\/webhook["\']',
            r'["\']\/webhooks\/[a-zA-Z0-9_\-\/]*["\']',
            r'["\']\/callback["\']',
            r'["\']\/internal\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/private\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/debug["\']',
            r'["\']\/debug\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/test\/[a-zA-Z0-9_\-\/]+["\']',
            r'["\']\/health["\']',
            r'["\']\/status["\']',
            r'["\']\/metrics["\']',
            r'["\']\/info["\']',
            r'["\']\/version["\']',
            r'["\']\/ping["\']',
            r'["\']\/upload["\']',
            r'["\']\/download\/[a-zA-Z0-9_\-\/]*["\']',
            r'["\']\/export\/[a-zA-Z0-9_\-\/]*["\']',
            r'["\']\/import\/[a-zA-Z0-9_\-\/]*["\']',
            r'["\']\/backup["\']',
            r'["\']\/logs["\']',
            r'["\']\/console["\']',
            r'["\']\/shell["\']',
            r'["\']\/exec["\']',
            r'["\']\/eval["\']',
            r'["\']\/search["\']',
            r'["\']\/query["\']',
            r'["\']\/payment["\']',
            r'["\']\/checkout["\']',
            r'["\']\/order["\']',
            r'["\']\/billing["\']',
            r'\.get\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'\.post\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'\.put\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'\.delete\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'\.patch\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'url:\s*[`"\']([^`"\']+)[`"\']',
            r'endpoint:\s*[`"\']([^`"\']+)[`"\']',
            r'baseURL:\s*[`"\']([^`"\']+)[`"\']',
            r'apiUrl:\s*[`"\']([^`"\']+)[`"\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                clean = match.strip('"\'`')
                if clean and len(clean) > 1 and len(clean) < 200:
                    if not any(junk in clean.lower() for junk in ['example', 'placeholder', 'your-', 'sample', 'test.com']):
                        if clean.startswith('/') or clean.startswith('http'):
                            endpoints.add(clean)
        
        return list(endpoints)[:300]
    
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
        
        return findings[:50]
    
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
                    
                    actual_confidence = self._calculate_confidence(value, secret_type, entropy, confidence)
                    
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
        
        return findings[:100]
    
    def _calculate_confidence(self, value: str, secret_type: str, entropy: float, base_confidence: str) -> str:
        high_confidence_types = [
            'aws_access_key', 'aws_secret', 'google_api_key', 'stripe_secret_key_live',
            'github_pat', 'gitlab_pat', 'sendgrid_api_key', 'slack_webhook',
            'discord_webhook', 'private_key_pem', 'openai_api_key', 'gcp_service_account'
        ]
        
        if secret_type in high_confidence_types:
            return 'high'
        
        if entropy >= 4.5:
            if base_confidence == 'low':
                return 'medium'
            return 'high' if base_confidence == 'medium' else base_confidence
        elif entropy >= 3.5:
            return base_confidence
        elif entropy >= 2.5:
            if base_confidence == 'high':
                return 'medium'
            return base_confidence
        else:
            return 'low'
    
    def _validate_secret(self, value: str, secret_type: str, line: str, position: int) -> bool:
        if self._is_likely_placeholder(value):
            return False
        
        for junk_pattern in self.JUNK_PATTERNS:
            if re.match(junk_pattern, value, re.IGNORECASE):
                return False
        
        if self._is_in_comment(line, position):
            return False
        
        if secret_type not in ['jwt_token', 'private_key_pem', 'gcp_service_account', 'certificate']:
            if self._is_in_minified_variable(line, position):
                return False
        
        entropy = self._calculate_entropy(value)
        
        if secret_type in ['api_key', 'secret_key', 'access_token', 'bearer_token']:
            if entropy < 2.0:
                return False
        
        if secret_type in ['aws_access_key', 'google_api_key', 'stripe_secret_key_live']:
            if entropy < 1.5:
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
        
        return findings[:50]
    
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
    
    def calculate_string_entropy(self, value: str) -> Tuple[float, str]:
        entropy = self._calculate_entropy(value)
        
        if entropy >= 4.5:
            classification = 'high'
        elif entropy >= 3.5:
            classification = 'medium'
        elif entropy >= 2.5:
            classification = 'low'
        else:
            classification = 'very_low'
        
        return entropy, classification
    
    def detect_high_entropy_strings(self, content: str, min_length: int = 20, max_length: int = 200) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        string_pattern = r'["\']([a-zA-Z0-9_\-/+=]{' + str(min_length) + ',' + str(max_length) + r'})["\']'
        
        for line_num, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            
            matches = re.finditer(string_pattern, line)
            for match in matches:
                value = match.group(1)
                
                if self._is_likely_placeholder(value):
                    continue
                
                if self._is_in_comment(line, match.start()):
                    continue
                
                entropy, classification = self.calculate_string_entropy(value)
                
                if entropy >= 4.5:
                    value_hash = hash(value)
                    if value_hash in self.seen_values:
                        continue
                    self.seen_values.add(value_hash)
                    
                    findings.append(Finding(
                        type='high_entropy_string',
                        value=self._mask_secret(value),
                        context=self._get_clean_context(line, match.start()),
                        line_number=line_num,
                        confidence='medium',
                        description=f'High entropy string detected (entropy: {entropy:.2f})',
                        entropy=entropy
                    ))
        
        return findings[:30]
    
    def detect_config_exposures(self, content: str) -> List[Finding]:
        findings = []
        seen = set()
        lines = content.split('\n')
        
        config_patterns = [
            (r'(?i)config\s*[=:]\s*\{[^}]+\}', 'config_object', 'Configuration object'),
            (r'(?i)(?:window|global)\.[A-Z_]+\s*=', 'global_config', 'Global configuration variable'),
            (r'(?i)__[A-Z_]+__\s*[=:]\s*', 'dunder_config', 'Dunder configuration'),
            (r'(?i)process\.env\.[A-Z_]+', 'env_reference', 'Environment variable reference'),
            (r'(?i)(?:secret|private|internal)[A-Za-z]*\s*[=:]\s*', 'secret_assignment', 'Secret variable assignment'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            
            for pattern, config_type, description in config_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(0)[:100]
                    
                    if value in seen:
                        continue
                    
                    if self._is_in_comment(line, match.start()):
                        continue
                    
                    seen.add(value)
                    findings.append(Finding(
                        type=config_type,
                        value=value,
                        context=self._get_clean_context(line, match.start()),
                        line_number=line_num,
                        confidence='low',
                        description=description
                    ))
        
        return findings[:30]
