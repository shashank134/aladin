"""
Data models for the modular reconnaissance pipeline.
Defines schemas for data persistence between phases.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import json
from datetime import datetime


class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class UrlType(Enum):
    ENDPOINT = "endpoint"
    API = "api"
    STATIC = "static"
    JAVASCRIPT = "javascript"
    OTHER = "other"


class JsCategory(Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"


@dataclass
class DiscoveredUrl:
    url: str
    domain: str
    subdomain: Optional[str] = None
    source: str = "unknown"
    url_type: UrlType = UrlType.OTHER
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "source": self.source,
            "url_type": self.url_type.value,
            "discovered_at": self.discovered_at,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DiscoveredUrl":
        data = data.copy()
        if "url_type" in data:
            data["url_type"] = UrlType(data["url_type"])
        return cls(**data)


@dataclass
class ReconResult:
    target: str
    scan_id: str
    started_at: str
    completed_at: Optional[str] = None
    urls_by_domain: Dict[str, List[DiscoveredUrl]] = field(default_factory=dict)
    total_urls: int = 0
    sources_used: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_urls": self.total_urls,
            "sources_used": self.sources_used,
            "urls_by_domain": {
                domain: [u.to_dict() for u in urls]
                for domain, urls in self.urls_by_domain.items()
            }
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ReconResult":
        data = data.copy()
        urls_by_domain = {}
        for domain, urls in data.get("urls_by_domain", {}).items():
            urls_by_domain[domain] = [DiscoveredUrl.from_dict(u) for u in urls]
        data["urls_by_domain"] = urls_by_domain
        return cls(**data)


@dataclass
class JsUrl:
    url: str
    category: JsCategory
    source_url: Optional[str] = None
    source_domain: Optional[str] = None
    discovery_method: str = "unknown"
    is_versioned: bool = False
    is_bundled: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "category": self.category.value,
            "source_url": self.source_url,
            "source_domain": self.source_domain,
            "discovery_method": self.discovery_method,
            "is_versioned": self.is_versioned,
            "is_bundled": self.is_bundled,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JsUrl":
        data = data.copy()
        if "category" in data:
            data["category"] = JsCategory(data["category"])
        return cls(**data)


@dataclass
class JsFilterResult:
    scan_id: str
    source_recon_id: Optional[str] = None
    filtered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    internal_js: List[JsUrl] = field(default_factory=list)
    external_js: List[JsUrl] = field(default_factory=list)
    total_js_urls: int = 0

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "source_recon_id": self.source_recon_id,
            "filtered_at": self.filtered_at,
            "total_js_urls": self.total_js_urls,
            "internal_js": [js.to_dict() for js in self.internal_js],
            "external_js": [js.to_dict() for js in self.external_js]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JsFilterResult":
        data = data.copy()
        data["internal_js"] = [JsUrl.from_dict(js) for js in data.get("internal_js", [])]
        data["external_js"] = [JsUrl.from_dict(js) for js in data.get("external_js", [])]
        return cls(**data)


@dataclass
class Finding:
    category: str
    finding_type: str
    value: str
    confidence: ConfidenceLevel
    context: str = ""
    line_number: Optional[int] = None
    entropy: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "finding_type": self.finding_type,
            "value": self.value,
            "confidence": self.confidence.value,
            "context": self.context,
            "line_number": self.line_number,
            "entropy": self.entropy,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = data.copy()
        if "confidence" in data:
            data["confidence"] = ConfidenceLevel(data["confidence"])
        return cls(**data)


@dataclass
class JsFileAnalysis:
    url: str
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"
    file_size: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "analyzed_at": self.analyzed_at,
            "status": self.status,
            "file_size": self.file_size,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JsFileAnalysis":
        data = data.copy()
        data["findings"] = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(**data)


@dataclass
class JsAnalysisResult:
    scan_id: str
    source_filter_id: Optional[str] = None
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    files_analyzed: List[JsFileAnalysis] = field(default_factory=list)
    total_files: int = 0
    total_findings: int = 0
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    findings_by_confidence: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "source_filter_id": self.source_filter_id,
            "analyzed_at": self.analyzed_at,
            "total_files": self.total_files,
            "total_findings": self.total_findings,
            "findings_by_category": self.findings_by_category,
            "findings_by_confidence": self.findings_by_confidence,
            "files_analyzed": [f.to_dict() for f in self.files_analyzed]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JsAnalysisResult":
        data = data.copy()
        data["files_analyzed"] = [JsFileAnalysis.from_dict(f) for f in data.get("files_analyzed", [])]
        return cls(**data)
