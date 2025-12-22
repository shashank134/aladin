"""
JavaScript Analysis Runner - Phase 3 of the modular pipeline.
Performs DEEP, SLOW static analysis on JavaScript files with HIGH-QUALITY findings.
Combines regex + entropy analysis + context-aware parsing for accurate detection.
"""

import re
import math
import asyncio
import aiohttp
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from urllib.parse import urlparse
import hashlib

from src.core.rate_limiter import RateLimiter
from src.core.logger import logger, set_silent
from src.models import (
    JsFilterResult, JsAnalysisResult, JsFileAnalysis, Finding, 
    ConfidenceLevel, JsUrl
)
from src.services.datastore import DataStore


class JsAnalysisRunner:
    
    ENTROPY_THRESHOLDS = {
        'low': 2.5,
        'medium': 3.5,
        'high': 4.5
    }
    
    CREDENTIALS_PATTERNS = [
        (r'(?i)(?:username|user_name|user)["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']', 'username', 'CREDENTIALS', 'medium'),
        (r'(?i)(?:password|passwd|pwd|pass)["\']?\s*[:=]\s*["\']([^"\']{4,100})["\']', 'password', 'CREDENTIALS', 'high'),
        (r'(?i)(?:admin[_-]?password|root[_-]?password)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', 'admin_password', 'CREDENTIALS', 'high'),
        (r'(?i)(?:default[_-]?password|initial[_-]?password)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', 'default_password', 'CREDENTIALS', 'high'),
        (r'(?i)(?:db[_-]?password|database[_-]?password)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', 'database_password', 'CREDENTIALS', 'high'),
        (r'(?i)Authorization["\']?\s*[:=]\s*["\']Basic\s+([a-zA-Z0-9+/=]{20,})["\']', 'basic_auth_header', 'CREDENTIALS', 'high'),
        (r'(?i)Authorization["\']?\s*[:=]\s*["\']Bearer\s+([a-zA-Z0-9_\-\.]{20,})["\']', 'bearer_auth_header', 'CREDENTIALS', 'high'),
        (r'(?i)x-api-key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'x_api_key_header', 'CREDENTIALS', 'high'),
        (r'(?i)(?:auth[_-]?user|authenticated[_-]?user)["\']?\s*[:=]\s*["\']([^"\']{3,})["\']', 'auth_user', 'CREDENTIALS', 'medium'),
        (r'(?i)(?:login|signin)["\']?\s*[:=]\s*\{[^}]*password[^}]*\}', 'login_credentials_object', 'CREDENTIALS', 'medium'),
    ]
    
    TOKENS_SECRETS_PATTERNS = [
        (r'eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}', 'jwt_token', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:bearer|token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{30,})["\']', 'bearer_token', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:access[_-]?token|accesstoken)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'access_token', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:refresh[_-]?token|refreshtoken)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'refresh_token', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:session[_-]?token|sessiontoken)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'session_token', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:oauth[_-]?token|oauth2[_-]?token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'oauth_token', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:oauth[_-]?secret|oauth2[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'oauth_secret', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:client[_-]?secret|clientsecret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'client_secret', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:app[_-]?secret|appsecret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', 'app_secret', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{20,})["\']', 'secret_key', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:signing[_-]?secret|signature[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'signing_secret', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:encryption[_-]?key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{16,})["\']', 'encryption_key', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:private[_-]?key|privatekey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{40,})["\']', 'private_key_value', 'TOKENS_SECRETS', 'high'),
        (r'(?i)(?:webhook[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'webhook_secret', 'TOKENS_SECRETS', 'high'),
        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'private_key_pem', 'TOKENS_SECRETS', 'high'),
        (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'pgp_private_key', 'TOKENS_SECRETS', 'high'),
    ]
    
    API_KEYS_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'API_KEYS', 'high'),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'aws_secret', 'API_KEYS', 'high'),
        (r'(?i)AWS_ACCESS_KEY_ID["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'aws_access_key_id', 'API_KEYS', 'high'),
        (r'(?i)AWS_SECRET_ACCESS_KEY["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'aws_secret_access_key', 'API_KEYS', 'high'),
        (r'(?i)aws[_-]?session[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{100,})["\']', 'aws_session_token', 'API_KEYS', 'high'),
        (r'AIza[0-9A-Za-z_-]{35}', 'google_api_key', 'API_KEYS', 'high'),
        (r'(?i)"type"\s*:\s*"service_account"', 'gcp_service_account', 'API_KEYS', 'high'),
        (r'(?i)client_email["\']?\s*[:=]\s*["\'][a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com["\']', 'gcp_service_account_email', 'API_KEYS', 'high'),
        (r'ya29\.[0-9A-Za-z_-]{50,}', 'google_oauth_token', 'API_KEYS', 'high'),
        (r'(?i)AccountKey\s*=\s*([a-zA-Z0-9/+=]{86,88})', 'azure_storage_key', 'API_KEYS', 'high'),
        (r'(?i)azure[_-]?(?:client[_-]?)?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.~]{34,})["\']', 'azure_client_secret', 'API_KEYS', 'high'),
        (r'(?i)DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+', 'azure_connection_string', 'API_KEYS', 'high'),
        (r'sk_live_[a-zA-Z0-9]{24,}', 'stripe_secret_live', 'API_KEYS', 'high'),
        (r'rk_live_[a-zA-Z0-9]{24,}', 'stripe_restricted_live', 'API_KEYS', 'high'),
        (r'pk_live_[a-zA-Z0-9]{24,}', 'stripe_public_live', 'API_KEYS', 'medium'),
        (r'sk_test_[a-zA-Z0-9]{24,}', 'stripe_secret_test', 'API_KEYS', 'medium'),
        (r'(?i)firebase[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{35,45})["\']', 'firebase_api_key', 'API_KEYS', 'high'),
        (r'(?i)"apiKey"\s*:\s*"AIza[0-9A-Za-z_-]{35}"', 'firebase_config_key', 'API_KEYS', 'high'),
        (r'(?i)PAYPAL_CLIENT_ID["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']', 'paypal_client_id', 'API_KEYS', 'high'),
        (r'(?i)PAYPAL_SECRET["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']', 'paypal_secret', 'API_KEYS', 'high'),
        (r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', 'paypal_braintree_token', 'API_KEYS', 'high'),
        (r'AC[a-f0-9]{32}', 'twilio_account_sid', 'API_KEYS', 'high'),
        (r'SK[a-f0-9]{32}', 'twilio_api_key', 'API_KEYS', 'high'),
        (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'sendgrid_api_key', 'API_KEYS', 'high'),
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'slack_token', 'API_KEYS', 'high'),
        (r'xox[baprs]-[0-9A-Za-z\-]{50,}', 'slack_token_new', 'API_KEYS', 'high'),
        (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9]+', 'slack_webhook', 'API_KEYS', 'high'),
        (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+', 'discord_webhook', 'API_KEYS', 'high'),
        (r'ghp_[a-zA-Z0-9]{36}', 'github_pat', 'API_KEYS', 'high'),
        (r'gho_[a-zA-Z0-9]{36}', 'github_oauth', 'API_KEYS', 'high'),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'github_fine_grained_pat', 'API_KEYS', 'high'),
        (r'glpat-[a-zA-Z0-9_\-]{20,}', 'gitlab_pat', 'API_KEYS', 'high'),
        (r'sk-[a-zA-Z0-9]{48}', 'openai_api_key', 'API_KEYS', 'high'),
        (r'sk-proj-[a-zA-Z0-9_-]{20,}', 'openai_project_key', 'API_KEYS', 'high'),
        (r'key-[a-f0-9]{32}', 'mailgun_key', 'API_KEYS', 'high'),
        (r'sq0atp-[a-zA-Z0-9_\-]{22}', 'square_access_token', 'API_KEYS', 'high'),
        (r'sq0csp-[a-zA-Z0-9_\-]{43}', 'square_oauth_secret', 'API_KEYS', 'high'),
        (r'shpat_[a-fA-F0-9]{32}', 'shopify_access_token', 'API_KEYS', 'high'),
        (r'shpss_[a-fA-F0-9]{32}', 'shopify_shared_secret', 'API_KEYS', 'high'),
        (r'NRAK-[A-Z0-9]{27}', 'newrelic_api_key', 'API_KEYS', 'high'),
        (r'dop_v1_[a-f0-9]{64}', 'digitalocean_pat', 'API_KEYS', 'high'),
        (r'npm_[a-zA-Z0-9]{36}', 'npm_token', 'API_KEYS', 'high'),
        (r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']', 'generic_api_key', 'API_KEYS', 'medium'),
        (r'(?i)GA-[0-9]+-[0-9]+', 'google_analytics_id', 'API_KEYS', 'low'),
        (r'(?i)UA-[0-9]+-[0-9]+', 'google_analytics_ua', 'API_KEYS', 'low'),
        (r'(?i)GTM-[A-Z0-9]+', 'google_tag_manager', 'API_KEYS', 'low'),
    ]
    
    UUIDS_PATTERNS = [
        (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}', 'uuid_v1', 'UUIDS_IDENTIFIERS', 'medium'),
        (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[2][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}', 'uuid_v2', 'UUIDS_IDENTIFIERS', 'medium'),
        (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[3][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}', 'uuid_v3', 'UUIDS_IDENTIFIERS', 'medium'),
        (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[4][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}', 'uuid_v4', 'UUIDS_IDENTIFIERS', 'low'),
        (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}', 'uuid_v5', 'UUIDS_IDENTIFIERS', 'medium'),
        (r'(?i)(?:user[_-]?id|userid|object[_-]?id|entity[_-]?id)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{10,40})["\']', 'internal_object_id', 'UUIDS_IDENTIFIERS', 'low'),
        (r'(?i)(?:customer[_-]?id|account[_-]?id|org[_-]?id)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,40})["\']', 'business_id', 'UUIDS_IDENTIFIERS', 'medium'),
        (r'(?i)(?:tenant[_-]?id|workspace[_-]?id|project[_-]?id)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,40})["\']', 'tenant_id', 'UUIDS_IDENTIFIERS', 'medium'),
    ]
    
    INTERNAL_REFS_PATTERNS = [
        (r'(?<![a-zA-Z0-9])localhost(?::\d+)?(?:/[^\s"\'<>]*)?', 'localhost', 'INTERNAL_REFERENCES', 'medium'),
        (r'(?<![a-zA-Z0-9\.])127\.0\.0\.1(?::\d+)?(?:/[^\s"\'<>]*)?', 'localhost_ip', 'INTERNAL_REFERENCES', 'medium'),
        (r'(?<![a-zA-Z0-9\.])0\.0\.0\.0(?::\d+)?', 'bind_all_ip', 'INTERNAL_REFERENCES', 'low'),
        (r'(?<![a-zA-Z0-9\.])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_10', 'INTERNAL_REFERENCES', 'high'),
        (r'(?<![a-zA-Z0-9\.])172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_172', 'INTERNAL_REFERENCES', 'high'),
        (r'(?<![a-zA-Z0-9\.])192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?', 'internal_ip_192', 'INTERNAL_REFERENCES', 'high'),
        (r'https?://[a-z0-9\-]+\.internal(?:\.[a-z]+)?(?::\d+)?[^\s"\'<>]*', 'internal_domain', 'INTERNAL_REFERENCES', 'high'),
        (r'https?://[a-z0-9\-]+\.local(?:host)?(?:\.[a-z]+)?(?::\d+)?[^\s"\'<>]*', 'local_domain', 'INTERNAL_REFERENCES', 'medium'),
        (r'https?://[a-z0-9\-]+\.(?:dev|develop|development)(?:\.[a-z]+)?(?::\d+)?[^\s"\'<>]*', 'dev_domain', 'INTERNAL_REFERENCES', 'medium'),
        (r'https?://[a-z0-9\-]+\.(?:test|testing)(?:\.[a-z]+)?(?::\d+)?[^\s"\'<>]*', 'test_domain', 'INTERNAL_REFERENCES', 'medium'),
        (r'https?://[a-z0-9\-]+\.(?:stage|staging)(?:\.[a-z]+)?(?::\d+)?[^\s"\'<>]*', 'staging_domain', 'INTERNAL_REFERENCES', 'medium'),
        (r'https?://(?:dev|test|stage|staging|qa|uat|sandbox)[a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]+[^\s"\'<>]*', 'env_subdomain', 'INTERNAL_REFERENCES', 'medium'),
        (r'https?://[a-z0-9\-]+\.(?:corp|corporate)(?:\.[a-z]+)?[^\s"\'<>]*', 'corp_domain', 'INTERNAL_REFERENCES', 'high'),
        (r'https?://[a-z0-9\-]+\.(?:intra|intranet)(?:\.[a-z]+)?[^\s"\'<>]*', 'intranet_domain', 'INTERNAL_REFERENCES', 'high'),
        (r'https?://[a-z0-9\-]+\.(?:priv|private)(?:\.[a-z]+)?[^\s"\'<>]*', 'private_domain', 'INTERNAL_REFERENCES', 'high'),
    ]
    
    INTERNAL_PATHS_PATTERNS = [
        (r'["\'](?:/api/v\d+/[a-zA-Z0-9/_\-]+)["\']', 'versioned_api', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/api/[a-zA-Z0-9/_\-]+)["\']', 'api_endpoint', 'INTERNAL_PATHS', 'low'),
        (r'["\'](?:/graphql|/gql)["\']', 'graphql_endpoint', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/admin[a-zA-Z0-9/_\-]*)["\']', 'admin_endpoint', 'INTERNAL_PATHS', 'high'),
        (r'["\'](?:/internal[a-zA-Z0-9/_\-]*)["\']', 'internal_endpoint', 'INTERNAL_PATHS', 'high'),
        (r'["\'](?:/debug[a-zA-Z0-9/_\-]*)["\']', 'debug_endpoint', 'INTERNAL_PATHS', 'high'),
        (r'["\'](?:/private[a-zA-Z0-9/_\-]*)["\']', 'private_endpoint', 'INTERNAL_PATHS', 'high'),
        (r'["\'](?:/hidden[a-zA-Z0-9/_\-]*)["\']', 'hidden_endpoint', 'INTERNAL_PATHS', 'high'),
        (r'["\'](?:/secret[a-zA-Z0-9/_\-]*)["\']', 'secret_endpoint', 'INTERNAL_PATHS', 'high'),
        (r'["\'](?:/deprecated[a-zA-Z0-9/_\-]*)["\']', 'deprecated_endpoint', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/legacy[a-zA-Z0-9/_\-]*)["\']', 'legacy_endpoint', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/test[a-zA-Z0-9/_\-]*)["\']', 'test_endpoint', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/dev[a-zA-Z0-9/_\-]*)["\']', 'dev_endpoint', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/beta[a-zA-Z0-9/_\-]*)["\']', 'beta_endpoint', 'INTERNAL_PATHS', 'low'),
        (r'["\'](?:/staging[a-zA-Z0-9/_\-]*)["\']', 'staging_endpoint', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/v0/[a-zA-Z0-9/_\-]+)["\']', 'v0_api', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/__[a-zA-Z0-9/_\-]+)["\']', 'dunder_endpoint', 'INTERNAL_PATHS', 'high'),
        (r'["\'](?:/\.well-known/[a-zA-Z0-9/_\-]+)["\']', 'well_known_endpoint', 'INTERNAL_PATHS', 'low'),
        (r'["\'](?:/health|/healthz|/healthcheck|/ready|/readyz|/live|/livez)["\']', 'health_endpoint', 'INTERNAL_PATHS', 'low'),
        (r'["\'](?:/metrics|/prometheus|/actuator)["\']', 'metrics_endpoint', 'INTERNAL_PATHS', 'medium'),
        (r'["\'](?:/swagger|/openapi|/docs|/api-docs)["\']', 'api_docs_endpoint', 'INTERNAL_PATHS', 'low'),
    ]
    
    CLOUD_DATA_PATTERNS = [
        (r'(?i)s3\.amazonaws\.com/[a-zA-Z0-9\-_.]+', 's3_bucket_url', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-_.]+\.s3\.amazonaws\.com', 's3_bucket_subdomain', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-_.]+\.s3\.[a-z0-9\-]+\.amazonaws\.com', 's3_bucket_regional', 'CLOUD_DATA', 'high'),
        (r'(?i)s3://[a-zA-Z0-9\-_.]+(?:/[^\s"\'<>]*)?', 's3_uri', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-]+\.blob\.core\.windows\.net', 'azure_blob_storage', 'CLOUD_DATA', 'high'),
        (r'(?i)storage\.googleapis\.com/[a-zA-Z0-9\-_.]+', 'gcs_bucket', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-_.]+\.storage\.googleapis\.com', 'gcs_bucket_subdomain', 'CLOUD_DATA', 'high'),
        (r'(?i)gs://[a-zA-Z0-9\-_.]+(?:/[^\s"\'<>]*)?', 'gcs_uri', 'CLOUD_DATA', 'high'),
        (r'(?i)firebase[a-zA-Z0-9\-]+\.firebaseio\.com', 'firebase_database_url', 'CLOUD_DATA', 'high'),
        (r'(?i)firebase[a-zA-Z0-9\-]+\.appspot\.com', 'firebase_storage_url', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-]+\.cloudfront\.net', 'cloudfront_cdn', 'CLOUD_DATA', 'medium'),
        (r'(?i)[a-zA-Z0-9\-]+\.azureedge\.net', 'azure_cdn', 'CLOUD_DATA', 'medium'),
        (r'(?i)[a-zA-Z0-9\-]+\.fastly\.net', 'fastly_cdn', 'CLOUD_DATA', 'medium'),
        (r'(?i)[a-zA-Z0-9\-]+\.akamaihd\.net', 'akamai_cdn', 'CLOUD_DATA', 'medium'),
        (r'(?i)[a-zA-Z0-9\-]+\.digitaloceanspaces\.com', 'digitalocean_spaces', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-]+\.backblazeb2\.com', 'backblaze_b2', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-]+\.r2\.cloudflarestorage\.com', 'cloudflare_r2', 'CLOUD_DATA', 'high'),
        (r'(?i)rds\.[a-z0-9\-]+\.amazonaws\.com', 'aws_rds', 'CLOUD_DATA', 'high'),
        (r'(?i)[a-zA-Z0-9\-]+\.elasticache\.[a-z0-9\-]+\.amazonaws\.com', 'aws_elasticache', 'CLOUD_DATA', 'high'),
    ]
    
    SENSITIVE_CONFIG_PATTERNS = [
        (r'(?i)debug\s*[:=]\s*(?:true|1|"true"|\'true\')', 'debug_enabled', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)DEBUG\s*[:=]\s*(?:true|1|"true"|\'true\')', 'DEBUG_flag', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)(?:dev[_-]?mode|development[_-]?mode)\s*[:=]\s*(?:true|1)', 'dev_mode', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)(?:test[_-]?mode|testing)\s*[:=]\s*(?:true|1)', 'test_mode', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)verbose\s*[:=]\s*(?:true|1)', 'verbose_mode', 'SENSITIVE_CONFIG', 'low'),
        (r'(?i)FEATURE_[A-Z_]+\s*[:=]\s*(?:true|false|1|0)', 'feature_flag_var', 'SENSITIVE_CONFIG', 'low'),
        (r'(?i)(?:feature[_-]?flag|ff)["\']?\s*[:=]\s*\{[^}]+\}', 'feature_flags_object', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)ENABLE_[A-Z_]+\s*[:=]\s*(?:true|false|1|0)', 'enable_flag', 'SENSITIVE_CONFIG', 'low'),
        (r'(?i)DISABLE_[A-Z_]+\s*[:=]\s*(?:true|false|1|0)', 'disable_flag', 'SENSITIVE_CONFIG', 'low'),
        (r'(?i)(?:bypass|skip)[_-]?(?:auth|authentication)\s*[:=]\s*(?:true|1)', 'auth_bypass', 'SENSITIVE_CONFIG', 'high'),
        (r'(?i)(?:disable[_-]?)?(?:csrf|xss)[_-]?(?:protection|check)?\s*[:=]\s*(?:false|0)', 'security_disabled', 'SENSITIVE_CONFIG', 'high'),
        (r'(?i)(?:ssl|tls)[_-]?verify\s*[:=]\s*(?:false|0)', 'ssl_verify_disabled', 'SENSITIVE_CONFIG', 'high'),
        (r'(?i)allow[_-]?cors[_-]?origin\s*[:=]\s*["\']?\*["\']?', 'cors_wildcard', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)environment["\']?\s*[:=]\s*["\'](?:development|staging|dev|test)["\']', 'environment_config', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)(?:node[_-]?)?env["\']?\s*[:=]\s*["\'](?:development|dev|test)["\']', 'node_env', 'SENSITIVE_CONFIG', 'medium'),
        (r'(?i)(?:log[_-]?)?level["\']?\s*[:=]\s*["\'](?:debug|trace|verbose)["\']', 'log_level', 'SENSITIVE_CONFIG', 'low'),
        (r'(?i)(?:permissions|roles|access)\s*[:=]\s*\[[^\]]*admin[^\]]*\]', 'hardcoded_permissions', 'SENSITIVE_CONFIG', 'high'),
        (r'(?i)(?:insecure|unsafe)[_-]?(?:mode|skip)\s*[:=]\s*(?:true|1)', 'insecure_mode', 'SENSITIVE_CONFIG', 'high'),
        (r'(?i)process\.env\.([A-Z_]+)', 'env_var_access', 'SENSITIVE_CONFIG', 'low'),
        (r'(?i)(?:backup|dump)[_-]?(?:url|path)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'backup_location', 'SENSITIVE_CONFIG', 'high'),
    ]
    
    DATABASE_PATTERNS = [
        (r'(?i)(?:mongodb(?:\+srv)?):\/\/[^\s"\'<>]+', 'mongodb_uri', 'DATABASE', 'high'),
        (r'(?i)postgres(?:ql)?:\/\/[^\s"\'<>]+', 'postgres_uri', 'DATABASE', 'high'),
        (r'(?i)mysql:\/\/[^\s"\'<>]+', 'mysql_uri', 'DATABASE', 'high'),
        (r'(?i)redis:\/\/[^\s"\'<>]+', 'redis_uri', 'DATABASE', 'high'),
        (r'(?i)amqp:\/\/[^\s"\'<>]+', 'rabbitmq_uri', 'DATABASE', 'high'),
        (r'(?i)mssql:\/\/[^\s"\'<>]+', 'mssql_uri', 'DATABASE', 'high'),
        (r'(?i)(?:jdbc:)?(?:oracle|mariadb):\/\/[^\s"\'<>]+', 'jdbc_uri', 'DATABASE', 'high'),
    ]
    
    AUTH_SESSION_PATTERNS = [
        (r'(?i)oauth[_-]?client[_-]?id["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{10,})["\']', 'oauth_client_id', 'AUTH_SESSION', 'high'),
        (r'(?i)oauth[_-]?client[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{10,})["\']', 'oauth_client_secret', 'AUTH_SESSION', 'high'),
        (r'(?i)redirect[_-]?uri["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'oauth_redirect_uri', 'AUTH_SESSION', 'medium'),
        (r'(?i)callback[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'oauth_callback_url', 'AUTH_SESSION', 'medium'),
        (r'(?i)csrf[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'csrf_token', 'AUTH_SESSION', 'high'),
        (r'(?i)_csrf["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'csrf_hidden_token', 'AUTH_SESSION', 'high'),
        (r'(?i)sso[_-]?(?:url|endpoint|config)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'sso_config', 'AUTH_SESSION', 'high'),
        (r'(?i)saml[_-]?(?:endpoint|issuer|metadata)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'saml_config', 'AUTH_SESSION', 'high'),
        (r'(?i)ldap[_-]?(?:url|server|bind)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'ldap_config', 'AUTH_SESSION', 'high'),
        (r'(?i)auth[_-]?bypass["\']?\s*[:=]\s*(?:true|1|"true"|\'true\')', 'auth_bypass_flag', 'AUTH_SESSION', 'high'),
        (r'(?i)skip[_-]?auth(?:entication)?["\']?\s*[:=]\s*(?:true|1)', 'skip_auth_flag', 'AUTH_SESSION', 'high'),
        (r'(?i)session[_-]?(?:secret|key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'session_secret', 'AUTH_SESSION', 'high'),
        (r'(?i)remember[_-]?me[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'remember_me_token', 'AUTH_SESSION', 'medium'),
        (r'(?i)jwt[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{16,})["\']', 'jwt_secret', 'AUTH_SESSION', 'high'),
        (r'(?i)jwt[_-]?(?:algorithm|alg)["\']?\s*[:=]\s*["\']([A-Z0-9]+)["\']', 'jwt_algorithm', 'AUTH_SESSION', 'medium'),
    ]
    
    NETWORK_INFRA_PATTERNS = [
        (r'(?i)kubernetes[_-]?service["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-\.]+)["\']', 'k8s_service', 'NETWORK_INFRA', 'high'),
        (r'(?i)k8s[_-]?(?:namespace|cluster|pod)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-]+)["\']', 'k8s_config', 'NETWORK_INFRA', 'high'),
        (r'(?i)docker[_-]?(?:image|container|registry)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-\./\:]+)["\']', 'docker_config', 'NETWORK_INFRA', 'medium'),
        (r'(?i)(?:microservice|service)[_-]?(?:url|endpoint|host)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'microservice_endpoint', 'NETWORK_INFRA', 'high'),
        (r'https?://[a-z0-9\-]+\.(?:svc\.cluster\.local|internal)[^\s"\'<>]*', 'k8s_internal_service', 'NETWORK_INFRA', 'high'),
        (r'(?i)load[_-]?balancer[_-]?(?:url|host)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'load_balancer', 'NETWORK_INFRA', 'high'),
        (r'(?i)(?:grpc|rpc)[_-]?(?:host|endpoint|server)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'grpc_endpoint', 'NETWORK_INFRA', 'high'),
        (r'(?i)consul[_-]?(?:host|addr|url)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'consul_config', 'NETWORK_INFRA', 'high'),
        (r'(?i)etcd[_-]?(?:host|endpoint)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'etcd_config', 'NETWORK_INFRA', 'high'),
        (r'(?i)zookeeper[_-]?(?:host|connect)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'zookeeper_config', 'NETWORK_INFRA', 'high'),
        (r'(?i)vault[_-]?(?:addr|url|token)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'vault_config', 'NETWORK_INFRA', 'high'),
    ]
    
    FRONTEND_FRAMEWORK_PATTERNS = [
        (r'(?i)webpack[_-]?(?:config|public[_-]?path)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'webpack_config', 'FRONTEND_FRAMEWORK', 'low'),
        (r'(?i)sourceMappingURL\s*=\s*([^\s]+\.map)', 'source_map_url', 'FRONTEND_FRAMEWORK', 'medium'),
        (r'(?i)//# sourceMappingURL=([^\s]+)', 'source_map_comment', 'FRONTEND_FRAMEWORK', 'medium'),
        (r'(?i)chunk[_-]?(?:name|url|path)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'chunk_loading', 'FRONTEND_FRAMEWORK', 'low'),
        (r'(?i)(?:commit|git)[_-]?hash["\']?\s*[:=]\s*["\']([a-f0-9]{7,40})["\']', 'commit_hash', 'FRONTEND_FRAMEWORK', 'medium'),
        (r'(?i)(?:build|version)[_-]?(?:id|number|timestamp)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'build_id', 'FRONTEND_FRAMEWORK', 'low'),
        (r'(?i)framework[_-]?version["\']?\s*[:=]\s*["\']([0-9\.]+)["\']', 'framework_version', 'FRONTEND_FRAMEWORK', 'low'),
        (r'(?i)cicd[_-]?(?:pipeline|job|build)[_-]?(?:id|name)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'cicd_pipeline', 'FRONTEND_FRAMEWORK', 'medium'),
        (r'(?i)jenkins[_-]?(?:url|job|build)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'jenkins_config', 'FRONTEND_FRAMEWORK', 'medium'),
        (r'(?i)(?:npm|yarn|pnpm)[_-]?(?:registry|token)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'package_registry', 'FRONTEND_FRAMEWORK', 'medium'),
    ]
    
    DEBUG_ARTIFACTS_PATTERNS = [
        (r'(?i)(?://|/\*)\s*TODO[:\s]([^\n\*/]+)', 'todo_comment', 'DEBUG_ARTIFACTS', 'low'),
        (r'(?i)(?://|/\*)\s*FIXME[:\s]([^\n\*/]+)', 'fixme_comment', 'DEBUG_ARTIFACTS', 'medium'),
        (r'(?i)(?://|/\*)\s*HACK[:\s]([^\n\*/]+)', 'hack_comment', 'DEBUG_ARTIFACTS', 'medium'),
        (r'(?i)(?://|/\*)\s*XXX[:\s]([^\n\*/]+)', 'xxx_comment', 'DEBUG_ARTIFACTS', 'low'),
        (r'(?i)(?://|/\*)\s*BUG[:\s]([^\n\*/]+)', 'bug_comment', 'DEBUG_ARTIFACTS', 'medium'),
        (r'(?i)console\.(?:log|debug|info|warn|error)\s*\(["\']([^"\']{10,})["\']', 'console_debug', 'DEBUG_ARTIFACTS', 'low'),
        (r'(?i)debugger\s*;', 'debugger_statement', 'DEBUG_ARTIFACTS', 'medium'),
        (r'(?i)(?:test|mock|fake|stub)[_-]?(?:user|password|email|api[_-]?key)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'test_credentials', 'DEBUG_ARTIFACTS', 'high'),
        (r'(?i)(?:demo|sample|example)[_-]?(?:account|user|data)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'demo_data', 'DEBUG_ARTIFACTS', 'medium'),
        (r'(?i)error[_-]?(?:message|template)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'error_template', 'DEBUG_ARTIFACTS', 'low'),
        (r'(?i)stack[_-]?trace["\']?\s*[:=]\s*(?:true|1)', 'stack_trace_enabled', 'DEBUG_ARTIFACTS', 'medium'),
        (r'(?i)verbose[_-]?(?:logging|errors?)["\']?\s*[:=]\s*(?:true|1)', 'verbose_logging', 'DEBUG_ARTIFACTS', 'medium'),
    ]
    
    BUSINESS_LOGIC_PATTERNS = [
        (r'(?i)(?:price|cost|amount)[_-]?(?:limit|max|min|threshold)["\']?\s*[:=]\s*["\']?([0-9]+)["\']?', 'pricing_threshold', 'BUSINESS_LOGIC', 'medium'),
        (r'(?i)discount[_-]?(?:code|percent|rate|max)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?', 'discount_config', 'BUSINESS_LOGIC', 'medium'),
        (r'(?i)rate[_-]?limit[_-]?(?:max|per|threshold)["\']?\s*[:=]\s*["\']?([0-9]+)["\']?', 'rate_limit_config', 'BUSINESS_LOGIC', 'medium'),
        (r'(?i)(?:max|min)[_-]?(?:retry|attempts|requests)["\']?\s*[:=]\s*["\']?([0-9]+)["\']?', 'retry_config', 'BUSINESS_LOGIC', 'low'),
        (r'(?i)fraud[_-]?(?:score|threshold|detection)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?', 'fraud_config', 'BUSINESS_LOGIC', 'high'),
        (r'(?i)(?:role|permission)[_-]?(?:matrix|mapping|check)["\']?\s*[:=]\s*\{', 'permission_matrix', 'BUSINESS_LOGIC', 'high'),
        (r'(?i)(?:is|has|can)[_-]?(?:admin|superuser|moderator)["\']?\s*[:=]', 'role_check', 'BUSINESS_LOGIC', 'high'),
        (r'(?i)feature[_-]?(?:entitled|enabled|allowed)["\']?\s*[:=]', 'feature_entitlement', 'BUSINESS_LOGIC', 'medium'),
        (r'(?i)subscription[_-]?(?:tier|plan|level)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'subscription_tier', 'BUSINESS_LOGIC', 'medium'),
        (r'(?i)(?:premium|pro|enterprise)[_-]?(?:features?|access)["\']?\s*[:=]', 'premium_access', 'BUSINESS_LOGIC', 'medium'),
    ]
    
    PRIVACY_DATA_PATTERNS = [
        (r'(?i)user[_-]?(?:email|phone|ssn|address)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'pii_field', 'PRIVACY_DATA', 'high'),
        (r'(?i)(?:personal|private)[_-]?data["\']?\s*[:=]\s*\{', 'personal_data_object', 'PRIVACY_DATA', 'high'),
        (r'(?i)gdpr[_-]?(?:consent|compliant|enabled)["\']?\s*[:=]', 'gdpr_config', 'PRIVACY_DATA', 'medium'),
        (r'(?i)ccpa[_-]?(?:consent|opt[_-]?out)["\']?\s*[:=]', 'ccpa_config', 'PRIVACY_DATA', 'medium'),
        (r'(?i)cookie[_-]?(?:consent|banner|policy)["\']?\s*[:=]', 'cookie_consent', 'PRIVACY_DATA', 'low'),
        (r'(?i)tracking[_-]?(?:opt[_-]?out|disabled|consent)["\']?\s*[:=]', 'tracking_config', 'PRIVACY_DATA', 'medium'),
        (r'(?i)data[_-]?retention[_-]?(?:days?|period)["\']?\s*[:=]\s*["\']?([0-9]+)["\']?', 'data_retention', 'PRIVACY_DATA', 'medium'),
        (r'(?i)anonymize[_-]?(?:user|data|ip)["\']?\s*[:=]', 'anonymization_config', 'PRIVACY_DATA', 'low'),
        (r'(?i)(?:credit[_-]?card|card[_-]?number|cvv|expir)[_-]?(?:pattern|format|field)', 'payment_field', 'PRIVACY_DATA', 'high'),
        (r'(?i)(?:ssn|social[_-]?security|tax[_-]?id)[_-]?(?:pattern|format|field)', 'ssn_field', 'PRIVACY_DATA', 'high'),
    ]
    
    FILE_STORAGE_PATTERNS = [
        (r'(?i)upload[_-]?(?:dir|path|folder)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'upload_directory', 'FILE_STORAGE', 'medium'),
        (r'(?i)(?:tmp|temp|temporary)[_-]?(?:dir|path|folder)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'temp_directory', 'FILE_STORAGE', 'medium'),
        (r'(?i)backup[_-]?(?:dir|path|folder)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'backup_directory', 'FILE_STORAGE', 'high'),
        (r'(?i)log[_-]?(?:dir|path|file)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'log_path', 'FILE_STORAGE', 'medium'),
        (r'(?i)static[_-]?(?:dir|path|root)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'static_path', 'FILE_STORAGE', 'low'),
        (r'(?i)media[_-]?(?:dir|path|root|url)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'media_path', 'FILE_STORAGE', 'low'),
        (r'(?i)\.(?:bak|backup|old|orig|tmp|temp|swp)\b', 'backup_file_extension', 'FILE_STORAGE', 'medium'),
        (r'(?i)/(?:backup|bak|dump|export|archive)/[^\s"\'<>]+', 'backup_path', 'FILE_STORAGE', 'high'),
        (r'(?i)(?:attachment|download)[_-]?path["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'attachment_path', 'FILE_STORAGE', 'medium'),
    ]
    
    SECURITY_WEAKNESS_PATTERNS = [
        (r'(?i)(?:csp|content[_-]?security[_-]?policy)["\']?\s*[:=]\s*["\']?(?:none|false|disabled)', 'csp_disabled', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)(?:cors|access[_-]?control)[_-]?(?:origin|allow)["\']?\s*[:=]\s*["\']?\*["\']?', 'cors_wildcard', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)(?:x[_-]?frame[_-]?options|frame[_-]?ancestors)["\']?\s*[:=]\s*["\']?(?:none|disabled)', 'xframe_disabled', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)integrity[_-]?check["\']?\s*[:=]\s*(?:false|0|disabled)', 'integrity_disabled', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)localStorage\.(?:setItem|getItem)\(["\'](?:token|jwt|auth|session|api[_-]?key)', 'localstorage_token', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)sessionStorage\.(?:setItem|getItem)\(["\'](?:token|jwt|auth|session|api[_-]?key)', 'sessionstorage_token', 'SECURITY_WEAKNESS', 'medium'),
        (r'(?i)document\.cookie\s*=\s*["\']?(?:token|jwt|auth|session)', 'cookie_token_js', 'SECURITY_WEAKNESS', 'medium'),
        (r'(?i)(?:secure|httponly)[_-]?cookie["\']?\s*[:=]\s*(?:false|0)', 'insecure_cookie', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)(?:eval|Function)\s*\(["\'][^"\']*\$\{', 'eval_usage', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)innerHTML\s*=\s*[^;]*(?:user|input|data|param)', 'innerhtml_xss', 'SECURITY_WEAKNESS', 'high'),
        (r'(?i)dangerouslySetInnerHTML\s*=', 'react_dangerous_html', 'SECURITY_WEAKNESS', 'medium'),
    ]
    
    PROTOCOL_COMM_PATTERNS = [
        (r'(?i)wss?://[^\s"\'<>]+', 'websocket_url', 'PROTOCOL_COMM', 'medium'),
        (r'(?i)(?:websocket|ws)[_-]?(?:url|endpoint|server)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'websocket_config', 'PROTOCOL_COMM', 'medium'),
        (r'(?i)(?:sse|event[_-]?source)[_-]?(?:url|endpoint)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'sse_endpoint', 'PROTOCOL_COMM', 'medium'),
        (r'(?i)mqtt://[^\s"\'<>]+', 'mqtt_broker', 'PROTOCOL_COMM', 'high'),
        (r'(?i)mqtt[_-]?(?:broker|host|url)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'mqtt_config', 'PROTOCOL_COMM', 'high'),
        (r'(?i)grpc[_-]?web[_-]?(?:url|endpoint)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'grpc_web_endpoint', 'PROTOCOL_COMM', 'medium'),
        (r'(?i)socket\.io[_-]?(?:url|server)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'socketio_url', 'PROTOCOL_COMM', 'medium'),
        (r'(?i)pusher[_-]?(?:key|app[_-]?id|cluster)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'pusher_config', 'PROTOCOL_COMM', 'medium'),
        (r'(?i)ably[_-]?(?:key|api[_-]?key)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'ably_config', 'PROTOCOL_COMM', 'high'),
    ]
    
    BUG_BOUNTY_SIGNALS_PATTERNS = [
        (r'(?i)(?:admin|superuser|root)[_-]?(?:check|flag|role)["\']?\s*[:=]', 'admin_capability', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:elevate|escalate)[_-]?(?:privilege|permission|role)', 'privilege_escalation', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:bypass|skip)[_-]?(?:authorization|auth[_-]?check|permission)', 'auth_bypass_hint', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:user|object|resource)[_-]?id\s*(?:===?|!==?)\s*(?:req|request|params?|query)', 'idor_pattern', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:if|when)\s*\(\s*(?:user|current[_-]?user)\.(?:id|role|is[_-]?admin)', 'client_side_auth', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)trust[_-]?(?:on[_-]?)?first[_-]?(?:use|request)', 'tofu_pattern', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:price|amount|quantity|discount)\s*=\s*(?:parseInt|Number|parseFloat)\s*\([^)]*(?:input|param|query)', 'client_side_pricing', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:hidden|internal)[_-]?(?:feature|function|endpoint)["\']?\s*[:=]', 'hidden_feature', 'BUG_BOUNTY_SIGNALS', 'medium'),
        (r'(?i)(?:backdoor|master[_-]?key|god[_-]?mode|cheat)', 'backdoor_hint', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:debug|test|dev)[_-]?(?:token|key|password)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'debug_credentials', 'BUG_BOUNTY_SIGNALS', 'high'),
        (r'(?i)(?:emergency|break[_-]?glass|override)[_-]?(?:access|password|key)', 'emergency_access', 'BUG_BOUNTY_SIGNALS', 'high'),
    ]
    
    JUNK_PATTERNS = [
        r'^[0-9]+$',
        r'^(.)\1+$',
        r'^(ab|abc|abcd|test|demo|example|sample|placeholder|changeme|todo|fixme|xxx|yyy|zzz|lorem|ipsum|null|undefined|none|empty|your|enter|insert|replace)$',
        r'^.*\$\{.*\}.*$',
        r'^.*\{\{.*\}\}.*$',
        r'^\$[A-Z_]+$',
        r'^__[A-Z_]+__$',
    ]
    
    RELAXED_PATTERNS = [
        (r'https?://[^\s"\'<>]+', 'url_found', 'URLS', 'low'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'email_found', 'EMAILS', 'low'),
        (r'/api/[^\s"\'<>]+', 'api_path', 'INTERNAL_PATHS', 'low'),
        (r'config\s*[=:]\s*\{', 'config_object', 'SENSITIVE_CONFIG', 'low'),
        (r'process\.env\.[A-Z_]+', 'env_reference', 'SENSITIVE_CONFIG', 'low'),
    ]
    
    COMMON_LIBS = [
        'jquery', 'react', 'angular', 'vue', 'bootstrap', 'lodash', 'moment',
        'axios', 'webpack', 'babel', 'polyfill', 'analytics', 'gtag', 'fbq',
        'maps.google', 'fonts.google', 'cdn.', 'unpkg.com', 'cdnjs.cloudflare',
        'jsdelivr.net', 'cloudflare.com/ajax', 'googletagmanager', 'facebook.net',
        'doubleclick.net', 'googlesyndication', 'google-analytics'
    ]
    
    def __init__(
        self,
        silent_mode: bool = False,
        output_dir: str = "recon_output",
        max_file_size: int = 5 * 1024 * 1024,
        timeout: int = 30,
        max_files: int = 100
    ):
        self.silent_mode = silent_mode
        self.datastore = DataStore(output_dir)
        self.max_file_size = max_file_size
        self.timeout = timeout
        self.max_files = max_files
        self.rate_limiter = RateLimiter(
            requests_per_second=2.0,
            max_concurrent=3,
            stealth_mode=True,
            silent_mode=silent_mode
        )
        self.seen_values: Set[str] = set()
        self.js_cache: Dict[str, str] = {}
        
        if silent_mode:
            set_silent(True)
        
        self._compile_patterns()
    
    def _compile_patterns(self):
        self.compiled_patterns = []
        all_patterns = [
            self.CREDENTIALS_PATTERNS,
            self.TOKENS_SECRETS_PATTERNS,
            self.API_KEYS_PATTERNS,
            self.UUIDS_PATTERNS,
            self.INTERNAL_REFS_PATTERNS,
            self.INTERNAL_PATHS_PATTERNS,
            self.CLOUD_DATA_PATTERNS,
            self.SENSITIVE_CONFIG_PATTERNS,
            self.DATABASE_PATTERNS,
            self.AUTH_SESSION_PATTERNS,
            self.NETWORK_INFRA_PATTERNS,
            self.FRONTEND_FRAMEWORK_PATTERNS,
            self.DEBUG_ARTIFACTS_PATTERNS,
            self.BUSINESS_LOGIC_PATTERNS,
            self.PRIVACY_DATA_PATTERNS,
            self.FILE_STORAGE_PATTERNS,
            self.SECURITY_WEAKNESS_PATTERNS,
            self.PROTOCOL_COMM_PATTERNS,
            self.BUG_BOUNTY_SIGNALS_PATTERNS,
            self.RELAXED_PATTERNS
        ]
        for pattern_group in all_patterns:
            for pattern, name, category, confidence in pattern_group:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    self.compiled_patterns.append((compiled, name, category, confidence))
                except re.error:
                    if not self.silent_mode:
                        logger.warning(f"Failed to compile pattern: {name}")
        
        self.compiled_junk_patterns = []
        for pattern in self.JUNK_PATTERNS:
            try:
                self.compiled_junk_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                pass
    
    def _calculate_entropy(self, data: str) -> float:
        if not data or len(data) < 8:
            return 0.0
        
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            probability = count / len(data)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_junk_value(self, value: str) -> bool:
        if not value or len(value) < 4:
            return True
        
        for pattern in self.compiled_junk_patterns:
            if pattern.match(value):
                return True
        
        if value.lower() in self.seen_values:
            return True
        
        return False
    
    def _extract_context(self, content: str, match_start: int, match_end: int, context_lines: int = 3) -> Tuple[str, int]:
        lines = content[:match_start].split('\n')
        line_number = len(lines)
        
        all_lines = content.split('\n')
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(all_lines), line_number + context_lines)
        
        context = '\n'.join(all_lines[start_line:end_line])
        
        if len(context) > 500:
            context = context[:500] + '...'
        
        return context, line_number
    
    def _get_confidence_level(self, base_confidence: str, entropy: float, value: str) -> ConfidenceLevel:
        confidence_map = {
            'high': ConfidenceLevel.HIGH,
            'medium': ConfidenceLevel.MEDIUM,
            'low': ConfidenceLevel.LOW
        }
        
        level = confidence_map.get(base_confidence, ConfidenceLevel.MEDIUM)
        
        if entropy >= self.ENTROPY_THRESHOLDS['high']:
            if level == ConfidenceLevel.MEDIUM:
                level = ConfidenceLevel.HIGH
            elif level == ConfidenceLevel.LOW:
                level = ConfidenceLevel.MEDIUM
        elif entropy < self.ENTROPY_THRESHOLDS['low'] and len(value) < 20:
            if level == ConfidenceLevel.HIGH:
                level = ConfidenceLevel.MEDIUM
            elif level == ConfidenceLevel.MEDIUM:
                level = ConfidenceLevel.LOW
        
        return level
    
    def _prettify_js(self, content: str) -> str:
        try:
            import jsbeautifier
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.max_preserve_newlines = 2
            return jsbeautifier.beautify(content, opts)
        except ImportError:
            return self._basic_prettify(content)
    
    def _basic_prettify(self, content: str) -> str:
        result = content
        result = re.sub(r'([{;])', r'\1\n', result)
        result = re.sub(r'([}])', r'\n\1', result)
        result = re.sub(r'\n+', '\n', result)
        return result
    
    def _analyze_content(self, content: str, url: str) -> List[Finding]:
        findings: List[Finding] = []
        
        try:
            prettified = self._prettify_js(content)
        except Exception:
            prettified = content
        
        for compiled_pattern, name, category, base_confidence in self.compiled_patterns:
            try:
                for match in compiled_pattern.finditer(content):
                    if match.groups():
                        value = match.group(1)
                    else:
                        value = match.group(0)
                    
                    if not value or self._is_junk_value(value):
                        continue
                    
                    if len(value) > 500:
                        value = value[:500]
                    
                    entropy = self._calculate_entropy(value)
                    
                    raw_line_number = len(content[:match.start()].split('\n'))
                    context, _ = self._extract_context(
                        content, match.start(), match.end()
                    )
                    
                    confidence = self._get_confidence_level(base_confidence, entropy, value)
                    
                    value_hash = hashlib.md5(f"{value}:{category}".encode()).hexdigest()
                    if value_hash in self.seen_values:
                        continue
                    self.seen_values.add(value_hash)
                    self.seen_values.add(value.lower())
                    
                    finding = Finding(
                        category=category,
                        finding_type=name,
                        value=value,
                        confidence=confidence,
                        context=context,
                        line_number=raw_line_number,
                        entropy=round(entropy, 2),
                        metadata={'url': url}
                    )
                    findings.append(finding)
            except Exception as e:
                if not self.silent_mode:
                    logger.warning(f"Pattern error {name}: {str(e)[:50]}")
        
        findings.sort(key=lambda f: (
            0 if f.confidence == ConfidenceLevel.HIGH else 
            1 if f.confidence == ConfidenceLevel.MEDIUM else 2,
            -f.entropy if f.entropy else 0
        ))
        
        return findings
    
    async def _download_js(self, url: str, session: aiohttp.ClientSession) -> Tuple[Optional[str], Optional[str]]:
        if url in self.js_cache:
            return self.js_cache[url], None
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/javascript, text/javascript, */*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'script',
                'Sec-Fetch-Mode': 'no-cors',
                'Sec-Fetch-Site': 'cross-site',
            }
            
            timeout = aiohttp.ClientTimeout(total=60)
            
            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status != 200:
                    return None, f"HTTP {response.status}"
                
                content_length = response.headers.get('Content-Length')
                if content_length:
                    try:
                        if int(content_length) > self.max_file_size:
                            return None, f"File too large: {content_length}"
                    except ValueError:
                        pass
                
                raw_content = await response.read()
                
                if len(raw_content) == 0:
                    return None, "Empty response"
                
                content_encoding = response.headers.get('Content-Encoding', '').lower()
                
                try:
                    if content_encoding == 'gzip':
                        import gzip
                        raw_content = gzip.decompress(raw_content)
                    elif content_encoding == 'br':
                        try:
                            import brotli
                            raw_content = brotli.decompress(raw_content)
                        except ImportError:
                            pass
                    elif content_encoding == 'deflate':
                        import zlib
                        raw_content = zlib.decompress(raw_content)
                except Exception:
                    pass
                
                content = None
                for encoding in ['utf-8', 'latin-1', 'ascii', 'iso-8859-1']:
                    try:
                        content = raw_content.decode(encoding, errors='replace')
                        break
                    except Exception:
                        continue
                
                if content is None:
                    content = raw_content.decode('utf-8', errors='replace')
                
                if len(content) < 50:
                    return None, "File too small"
                
                if len(content) > self.max_file_size:
                    content = content[:self.max_file_size]
                
                self.js_cache[url] = content
                return content, None
            
        except asyncio.TimeoutError:
            return None, "Timeout"
        except aiohttp.ClientError as e:
            return None, f"Client error: {str(e)[:80]}"
        except Exception as e:
            return None, str(e)[:100]
    
    async def _analyze_js_file(
        self, 
        url: str, 
        session: aiohttp.ClientSession
    ) -> JsFileAnalysis:
        analysis = JsFileAnalysis(url=url)
        
        content, error = await self._download_js(url, session)
        
        if error:
            analysis.status = "failed"
            analysis.error = error
            return analysis
        
        if not content:
            analysis.status = "failed"
            analysis.error = "No content"
            return analysis
        
        analysis.file_size = len(content)
        
        try:
            findings = self._analyze_content(content, url)
            analysis.findings = findings
            analysis.status = "completed"
        except Exception as e:
            analysis.status = "error"
            analysis.error = str(e)[:200]
        
        return analysis
    
    def _filter_library_urls(self, urls: List[str]) -> List[str]:
        filtered = []
        for url in urls:
            url_lower = url.lower()
            is_lib = any(lib in url_lower for lib in self.COMMON_LIBS)
            if not is_lib:
                filtered.append(url)
        return filtered
    
    async def run_async(
        self,
        target: str,
        js_filter_result: Optional[JsFilterResult] = None,
        js_urls: Optional[List[str]] = None,
        analyze_external: bool = False
    ) -> JsAnalysisResult:
        scan_id = self.datastore.generate_scan_id()
        source_filter_id = js_filter_result.scan_id if js_filter_result else None
        
        if not self.silent_mode:
            logger.info(f"Starting JS analysis for: {target}")
            logger.info(f"Scan ID: {scan_id}")
        
        urls_to_analyze: List[str] = []
        
        if js_filter_result:
            for js_url in js_filter_result.internal_js:
                urls_to_analyze.append(js_url.url)
            
            if analyze_external:
                for js_url in js_filter_result.external_js:
                    urls_to_analyze.append(js_url.url)
        
        user_provided_urls = []
        if js_urls:
            user_provided_urls = list(js_urls)
            urls_to_analyze.extend(js_urls)
        
        if not js_filter_result and not js_urls:
            existing_filter = self.datastore.load_js_filter_result(target)
            if existing_filter:
                source_filter_id = existing_filter.scan_id
                for js_url in existing_filter.internal_js:
                    urls_to_analyze.append(js_url.url)
                if analyze_external:
                    for js_url in existing_filter.external_js:
                        urls_to_analyze.append(js_url.url)
        
        urls_to_analyze = list(set(urls_to_analyze))
        urls_to_analyze = self._filter_library_urls(urls_to_analyze)
        
        for url in user_provided_urls:
            if url not in urls_to_analyze:
                urls_to_analyze.append(url)
        urls_to_analyze = urls_to_analyze[:self.max_files]
        
        if not self.silent_mode:
            logger.info(f"Analyzing {len(urls_to_analyze)} JS files...")
        
        semaphore = asyncio.Semaphore(10)

        async def bounded_analyze(url, session):
            async with semaphore:
                return await self._analyze_js_file(url, session)

        files_analyzed: List[JsFileAnalysis] = []
        
        connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=120)
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/javascript, text/javascript, */*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [bounded_analyze(url, session) for url in urls_to_analyze]
            files_analyzed = await asyncio.gather(*tasks)
            for i, url in enumerate(urls_to_analyze):
                if not self.silent_mode and (i + 1) % 10 == 0:
                    logger.info(f"Progress: {i + 1}/{len(urls_to_analyze)}")
                
                analysis = await self._analyze_js_file(url, session)
                files_analyzed.append(analysis)
                
                await asyncio.sleep(0.1)
        
        total_findings = sum(len(f.findings) for f in files_analyzed)
        
        findings_by_category: Dict[str, int] = {}
        findings_by_confidence: Dict[str, int] = {}
        
        for file_analysis in files_analyzed:
            for finding in file_analysis.findings:
                cat = finding.category
                findings_by_category[cat] = findings_by_category.get(cat, 0) + 1
                
                conf = finding.confidence.value
                findings_by_confidence[conf] = findings_by_confidence.get(conf, 0) + 1
        
        result = JsAnalysisResult(
            scan_id=scan_id,
            source_filter_id=source_filter_id,
            analyzed_at=datetime.now().isoformat(),
            files_analyzed=files_analyzed,
            total_files=len(files_analyzed),
            total_findings=total_findings,
            findings_by_category=findings_by_category,
            findings_by_confidence=findings_by_confidence
        )
        
        filepath = self.datastore.save_js_analysis_result(target, result)
        
        if not self.silent_mode:
            logger.info(f"Analysis results saved to: {filepath}")
            logger.info(f"Total files analyzed: {len(files_analyzed)}")
            logger.info(f"Total findings: {total_findings}")
            logger.info(f"Findings by category: {findings_by_category}")
            logger.info(f"Findings by confidence: {findings_by_confidence}")
            
            successful = sum(1 for f in files_analyzed if f.status == "completed")
            failed = sum(1 for f in files_analyzed if f.status == "failed")
            logger.info(f"Successful downloads: {successful}, Failed: {failed}")
        
        return result
    
    def run(
        self,
        target: str,
        js_filter_result: Optional[JsFilterResult] = None,
        js_urls: Optional[List[str]] = None,
        analyze_external: bool = False
    ) -> JsAnalysisResult:
        return asyncio.run(self.run_async(
            target, js_filter_result, js_urls, analyze_external
        ))
    
    def run_from_filter(self, js_filter_result: JsFilterResult, analyze_external: bool = False) -> JsAnalysisResult:
        target = "unknown"
        if js_filter_result.internal_js:
            url = js_filter_result.internal_js[0].url
            parsed = urlparse(url)
            target = parsed.netloc
        
        return self.run(target, js_filter_result=js_filter_result, analyze_external=analyze_external)
    
    def run_from_urls(self, target: str, urls: List[str]) -> JsAnalysisResult:
        return self.run(target, js_urls=urls)
