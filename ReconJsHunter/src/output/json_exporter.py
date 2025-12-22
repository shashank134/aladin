"""
JSON export functionality.
Creates structured JSON output files for all collected data.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

from src.collectors.base import CollectedData
from src.models import JsAnalysisResult, JsFileAnalysis, Finding
from src.core.logger import logger


class JSONExporter:
    
    def __init__(self, output_dir: str = "recon_output"):
        self.output_dir = output_dir
    
    def export_full_report(self, domain: str, collected_data: Dict[str, CollectedData],
                           js_result: JsAnalysisResult,
                           categorized_urls: Dict[str, List[str]]) -> str:
        target_dir = self._create_target_dir(domain)
        
        report = {
            'meta': {
                'domain': domain,
                'scan_time': datetime.now().isoformat(),
                'tool': 'ReconHunter',
                'version': '1.0.0'
            },
            'summary': self._generate_summary(collected_data, js_result, categorized_urls),
            'main_domain': {
                'urls': categorized_urls.get('main_domain', []),
                'endpoints': categorized_urls.get('endpoints', [])
            },
            'subdomains': self._organize_subdomains(collected_data, categorized_urls),
            'javascript': {
                'files': categorized_urls.get('javascript', []),
                'analysis': js_result.to_dict() if js_result else {}
            },
            'sources': {name: data.to_dict() for name, data in collected_data.items()},
            'findings': self._aggregate_findings(js_result)
        }
        
        report_path = os.path.join(target_dir, 'full_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._export_individual_sections(target_dir, report)
        
        logger.info(f"Report exported to {target_dir}")
        
        return target_dir
    
    def _create_target_dir(self, domain: str) -> str:
        safe_domain = domain.replace(':', '_').replace('/', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_dir = os.path.join(self.output_dir, f"{safe_domain}_{timestamp}")
        
        os.makedirs(target_dir, exist_ok=True)
        os.makedirs(os.path.join(target_dir, 'js_analysis'), exist_ok=True)
        
        return target_dir
    
    def _generate_summary(self, collected_data: Dict[str, CollectedData],
                          js_result: JsAnalysisResult,
                          categorized_urls: Dict[str, List[str]]) -> Dict:
        total_urls = sum(len(data.urls) for data in collected_data.values())
        total_subdomains = set()
        for data in collected_data.values():
            total_subdomains.update(data.subdomains)
        
        total_findings = js_result.total_findings if js_result else 0
        files_analyzed = len(js_result.files_analyzed) if js_result else 0
        high_confidence = js_result.findings_by_confidence.get('high', 0) if js_result else 0
        internal_refs = js_result.findings_by_category.get('INTERNAL_REFERENCES', 0) if js_result else 0
        
        return {
            'total_urls': total_urls,
            'unique_urls': len(categorized_urls.get('all', [])),
            'total_subdomains': len(total_subdomains),
            'total_js_files': len(categorized_urls.get('javascript', [])),
            'js_files_analyzed': files_analyzed,
            'total_endpoints': len(categorized_urls.get('endpoints', [])),
            'total_secrets_found': total_findings,
            'high_confidence_secrets': high_confidence,
            'total_internal_refs': internal_refs,
            'sources_used': list(collected_data.keys())
        }
    
    def _organize_subdomains(self, collected_data: Dict[str, CollectedData],
                              categorized_urls: Dict[str, List[str]]) -> Dict:
        subdomains = {}
        
        all_subdomains = set()
        for data in collected_data.values():
            all_subdomains.update(data.subdomains)
        
        subdomain_urls = categorized_urls.get('subdomain_urls', {})
        
        for subdomain in sorted(all_subdomains):
            subdomains[subdomain] = {
                'urls': subdomain_urls.get(subdomain, []),
                'url_count': len(subdomain_urls.get(subdomain, []))
            }
        
        return subdomains
    
    def _aggregate_findings(self, js_result: JsAnalysisResult) -> Dict:
        findings = {
            'secrets': {'high': [], 'medium': [], 'low': []},
            'internal_references': [],
            'sensitive_data': [],
            'api_endpoints': []
        }
        
        if not js_result:
            return findings
        
        for file_analysis in js_result.files_analyzed:
            for finding in file_analysis.findings:
                finding_dict = finding.to_dict()
                finding_dict['source_file'] = file_analysis.url
                
                confidence = finding.confidence.value if hasattr(finding.confidence, 'value') else finding.confidence
                
                if finding.category in ['API_KEYS', 'TOKENS_SECRETS', 'CREDENTIALS', 'DATABASE']:
                    findings['secrets'][confidence].append(finding_dict)
                elif finding.category == 'INTERNAL_REFERENCES':
                    findings['internal_references'].append(finding_dict)
                elif finding.category == 'INTERNAL_PATHS':
                    findings['api_endpoints'].append({
                        'endpoint': finding.value,
                        'source_file': file_analysis.url,
                        'finding_type': finding.finding_type,
                        'confidence': confidence
                    })
                    findings['internal_references'].append(finding_dict)
                elif finding.category in ['SENSITIVE_CONFIG', 'PRIVACY_DATA']:
                    findings['sensitive_data'].append(finding_dict)
        
        return findings
    
    def _export_individual_sections(self, target_dir: str, report: Dict):
        with open(os.path.join(target_dir, 'urls.json'), 'w') as f:
            json.dump({
                'main_domain': report['main_domain'],
                'subdomains': list(report['subdomains'].keys())
            }, f, indent=2)
        
        with open(os.path.join(target_dir, 'javascript.json'), 'w') as f:
            json.dump(report['javascript'], f, indent=2)
        
        with open(os.path.join(target_dir, 'findings.json'), 'w') as f:
            json.dump(report['findings'], f, indent=2)
        
        with open(os.path.join(target_dir, 'summary.json'), 'w') as f:
            json.dump(report['summary'], f, indent=2)
