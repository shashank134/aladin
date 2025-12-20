"""
Configuration management for ReconHunter.
Handles all configurable parameters for rate limiting, timeouts, and behavior.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RateLimitConfig:
    requests_per_second: float = 2.0
    max_concurrent: int = 5
    retry_attempts: int = 3
    retry_delay: float = 2.0
    timeout: int = 30


@dataclass
class CollectorConfig:
    enabled: bool = True
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    api_key: Optional[str] = None


@dataclass
class Config:
    output_dir: str = "recon_output"
    user_agent: str = "ReconHunter/1.0 (Security Research Tool)"
    
    wayback: CollectorConfig = field(default_factory=CollectorConfig)
    urlscan: CollectorConfig = field(default_factory=CollectorConfig)
    alienvault: CollectorConfig = field(default_factory=CollectorConfig)
    commoncrawl: CollectorConfig = field(default_factory=CollectorConfig)
    live_discovery: CollectorConfig = field(default_factory=CollectorConfig)
    
    js_analysis: bool = True
    max_js_size: int = 10 * 1024 * 1024
    
    verbose: bool = False
    debug: bool = False
    
    @classmethod
    def from_yaml(cls, path: str) -> 'Config':
        if not os.path.exists(path):
            return cls()
        
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        config = cls()
        
        if 'output_dir' in data:
            config.output_dir = data['output_dir']
        if 'user_agent' in data:
            config.user_agent = data['user_agent']
        if 'verbose' in data:
            config.verbose = data['verbose']
        if 'debug' in data:
            config.debug = data['debug']
        
        for collector in ['wayback', 'urlscan', 'alienvault', 'commoncrawl', 'live_discovery']:
            if collector in data:
                cdata = data[collector]
                cconfig = getattr(config, collector)
                if 'enabled' in cdata:
                    cconfig.enabled = cdata['enabled']
                if 'api_key' in cdata:
                    cconfig.api_key = cdata['api_key']
                if 'rate_limit' in cdata:
                    rl = cdata['rate_limit']
                    cconfig.rate_limit = RateLimitConfig(
                        requests_per_second=rl.get('requests_per_second', 2.0),
                        max_concurrent=rl.get('max_concurrent', 5),
                        retry_attempts=rl.get('retry_attempts', 3),
                        retry_delay=rl.get('retry_delay', 2.0),
                        timeout=rl.get('timeout', 30)
                    )
        
        return config
    
    def to_dict(self) -> Dict:
        return {
            'output_dir': self.output_dir,
            'user_agent': self.user_agent,
            'js_analysis': self.js_analysis,
            'max_js_size': self.max_js_size,
            'verbose': self.verbose,
            'debug': self.debug
        }


def get_default_config() -> Config:
    config = Config()
    
    config.urlscan.api_key = os.environ.get('URLSCAN_API_KEY')
    config.alienvault.api_key = os.environ.get('ALIENVAULT_API_KEY')
    
    return config
