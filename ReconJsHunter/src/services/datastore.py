"""
DataStore service for persisting and loading pipeline data between phases.
Handles JSON serialization/deserialization of recon, filter, and analysis results.
"""

import json
import os
from pathlib import Path
from typing import Optional, List
from datetime import datetime
import uuid

from src.models import (
    ReconResult, JsFilterResult, JsAnalysisResult,
    DiscoveredUrl, JsUrl, JsFileAnalysis
)


class DataStore:
    
    RECON_FILE = "recon.json"
    JS_URLS_FILE = "js_urls.json"
    JS_FINDINGS_FILE = "js_findings.json"
    
    def __init__(self, output_dir: str = "recon_output"):
        self.base_dir = Path(output_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_target_dir(self, target: str) -> Path:
        safe_target = target.replace("/", "_").replace(":", "_").replace(".", "_")
        target_dir = self.base_dir / safe_target
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir
    
    def generate_scan_id(self) -> str:
        return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    
    def save_recon_result(self, result: ReconResult) -> str:
        target_dir = self._get_target_dir(result.target)
        filepath = target_dir / self.RECON_FILE
        
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        return str(filepath)
    
    def load_recon_result(self, target: str) -> Optional[ReconResult]:
        target_dir = self._get_target_dir(target)
        filepath = target_dir / self.RECON_FILE
        
        if not filepath.exists():
            return None
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return ReconResult.from_dict(data)
        except Exception:
            return None
    
    def load_recon_from_file(self, filepath: str) -> Optional[ReconResult]:
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return ReconResult.from_dict(data)
        except Exception:
            return None
    
    def save_js_filter_result(self, target: str, result: JsFilterResult) -> str:
        target_dir = self._get_target_dir(target)
        filepath = target_dir / self.JS_URLS_FILE
        
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        return str(filepath)
    
    def load_js_filter_result(self, target: str) -> Optional[JsFilterResult]:
        target_dir = self._get_target_dir(target)
        filepath = target_dir / self.JS_URLS_FILE
        
        if not filepath.exists():
            return None
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return JsFilterResult.from_dict(data)
        except Exception:
            return None
    
    def load_js_filter_from_file(self, filepath: str) -> Optional[JsFilterResult]:
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return JsFilterResult.from_dict(data)
        except Exception:
            return None
    
    def save_js_analysis_result(self, target: str, result: JsAnalysisResult) -> str:
        target_dir = self._get_target_dir(target)
        filepath = target_dir / self.JS_FINDINGS_FILE
        
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        return str(filepath)
    
    def load_js_analysis_result(self, target: str) -> Optional[JsAnalysisResult]:
        target_dir = self._get_target_dir(target)
        filepath = target_dir / self.JS_FINDINGS_FILE
        
        if not filepath.exists():
            return None
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return JsAnalysisResult.from_dict(data)
        except Exception:
            return None
    
    def load_url_list(self, filepath: str) -> List[str]:
        urls = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
        except Exception:
            pass
        return urls
    
    def get_all_targets(self) -> List[str]:
        targets = []
        if self.base_dir.exists():
            for item in self.base_dir.iterdir():
                if item.is_dir():
                    targets.append(item.name)
        return targets
    
    def get_target_status(self, target: str) -> dict:
        target_dir = self._get_target_dir(target)
        status = {
            "has_recon": (target_dir / self.RECON_FILE).exists(),
            "has_js_urls": (target_dir / self.JS_URLS_FILE).exists(),
            "has_findings": (target_dir / self.JS_FINDINGS_FILE).exists()
        }
        return status
