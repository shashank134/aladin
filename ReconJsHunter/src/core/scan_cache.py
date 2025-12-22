"""
Scan cache module for saving and resuming scan state.
Provides atomic file writes to prevent corruption during interrupts.
"""

import json
import os
import tempfile
import shutil
from datetime import datetime
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, asdict


@dataclass
class CacheEntry:
    source: str
    completed: bool
    urls: List[str]
    subdomains: List[str]
    js_files: List[str]
    endpoints: List[str]
    errors: List[str]
    collected_at: str


class ScanCache:
    
    CACHE_FILENAME = ".recon_cache.json"
    CACHE_VERSION = "1.0"
    
    def __init__(self, output_dir: str, domain: str):
        self.output_dir = output_dir
        self.domain = domain
        self.cache_path = os.path.join(output_dir, self.CACHE_FILENAME)
        self._state: Dict[str, Any] = {}
    
    def _ensure_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
    
    def _atomic_write(self, data: Dict):
        self._ensure_output_dir()
        
        fd, temp_path = tempfile.mkstemp(
            suffix='.json',
            prefix='.recon_cache_',
            dir=self.output_dir
        )
        
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            shutil.move(temp_path, self.cache_path)
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise
    
    def save_state(self, collected_data: Dict, progress: str = "in_progress"):
        now = datetime.utcnow().isoformat()
        
        cache_entries = {}
        for source_name, data in collected_data.items():
            cache_entries[source_name] = {
                'source': source_name,
                'completed': True,
                'urls': list(data.urls) if hasattr(data, 'urls') else [],
                'subdomains': list(data.subdomains) if hasattr(data, 'subdomains') else [],
                'js_files': list(data.js_files) if hasattr(data, 'js_files') else [],
                'endpoints': list(data.endpoints) if hasattr(data, 'endpoints') else [],
                'errors': list(data.errors) if hasattr(data, 'errors') else [],
                'collected_at': now
            }
        
        state = {
            'version': self.CACHE_VERSION,
            'domain': self.domain,
            'started_at': self._state.get('started_at', now),
            'updated_at': now,
            'progress': progress,
            'sources': cache_entries
        }
        
        self._state = state
        self._atomic_write(state)
    
    def load_state(self) -> Optional[Dict]:
        if not os.path.exists(self.cache_path):
            return None
        
        try:
            with open(self.cache_path, 'r') as f:
                state = json.load(f)
            
            if state.get('version') != self.CACHE_VERSION:
                return None
            
            if state.get('domain') != self.domain:
                return None
            
            self._state = state
            return state
            
        except (json.JSONDecodeError, IOError):
            return None
    
    def is_resumable(self) -> bool:
        state = self.load_state()
        if not state:
            return False
        
        if state.get('progress') == 'completed':
            return False
        
        sources = state.get('sources', {})
        return len(sources) > 0
    
    def get_cached_sources(self) -> List[str]:
        state = self.load_state()
        if not state:
            return []
        
        sources = state.get('sources', {})
        return [
            name for name, data in sources.items()
            if data.get('completed', False)
        ]
    
    def get_cached_data(self, source_name: str) -> Optional[Dict]:
        state = self.load_state()
        if not state:
            return None
        
        sources = state.get('sources', {})
        return sources.get(source_name)
    
    def get_all_cached_data(self) -> Dict[str, Dict]:
        state = self.load_state()
        if not state:
            return {}
        
        return state.get('sources', {})
    
    def get_started_at(self) -> Optional[str]:
        state = self.load_state()
        if not state:
            return None
        return state.get('started_at')
    
    def mark_completed(self):
        if self._state:
            self._state['progress'] = 'completed'
            self._state['updated_at'] = datetime.utcnow().isoformat()
            self._atomic_write(self._state)
    
    def cleanup(self):
        if os.path.exists(self.cache_path):
            try:
                os.unlink(self.cache_path)
            except OSError:
                pass
    
    def get_cache_info(self) -> Optional[Dict]:
        state = self.load_state()
        if not state:
            return None
        
        return {
            'domain': state.get('domain'),
            'started_at': state.get('started_at'),
            'updated_at': state.get('updated_at'),
            'progress': state.get('progress'),
            'cached_sources': list(state.get('sources', {}).keys()),
            'total_urls': sum(
                len(s.get('urls', []))
                for s in state.get('sources', {}).values()
            )
        }
