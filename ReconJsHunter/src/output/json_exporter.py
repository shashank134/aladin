"""
JSON export functionality.
Creates structured JSON output files for all collected data.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

from src.collectors.base import CollectedData
from src.analyzers.js_analyzer import JSAnalysisResult
from src.core.logger import logger


class JSONExporter:
    
    def __init__(self, output_dir: str = "recon_output"):
        self.output_dir = output_dir
    
    def export_full_report(self, domain: str, collected_data: Dict[str, CollectedData],
                           js_results: List[JSAnalysisResult],
                           categorized_urls: Dict[str, List[str]]) -> str:
        target_dir = self._create_target_dir(domain)
        
        report = {
            'meta': {
                'domain': domain,
                'scan_time': datetime.now().isoformat(),
                'tool': 'ReconHunter',
                'version': '1.0.0'
            },
            'summary': self._generate_summary(collected_data, js_results, categorized_urls),
            'main_domain': {
                'urls': categorized_urls.get('main_domain', []),
                'endpoints': categorized_urls.get('endpoints', [])
            },
            'subdomains': self._organize_subdomains(collected_data, categorized_urls),
            'javascript': {
                'files': categorized_urls.get('javascript', []),
                'analysis': [r.to_dict() for r in js_results]
            },
            'sources': {name: data.to_dict() for name, data in collected_data.items()},
            'findings': self._aggregate_findings(js_results)
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
                          js_results: List[JSAnalysisResult],
                          categorized_urls: Dict[str, List[str]]) -> Dict:
        total_urls = sum(len(data.urls) for data in collected_data.values())
        total_subdomains = set()
        for data in collected_data.values():
            total_subdomains.update(data.subdomains)
        
        total_secrets = sum(len(r.secrets) for r in js_results)
        total_internal = sum(len(r.internal_refs) for r in js_results)
        
        high_confidence_secrets = sum(
            1 for r in js_results for s in r.secrets if s.confidence == 'high'
        )
        
        return {
            'total_urls': total_urls,
            'unique_urls': len(categorized_urls.get('all', [])),
            'total_subdomains': len(total_subdomains),
            'total_js_files': len(categorized_urls.get('javascript', [])),
            'js_files_analyzed': len(js_results),
            'total_endpoints': len(categorized_urls.get('endpoints', [])),
            'total_secrets_found': total_secrets,
            'high_confidence_secrets': high_confidence_secrets,
            'total_internal_refs': total_internal,
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
    
    def _aggregate_findings(self, js_results: List[JSAnalysisResult]) -> Dict:
        findings = {
            'secrets': {'high': [], 'medium': [], 'low': []},
            'internal_references': [],
            'sensitive_data': [],
            'api_endpoints': []
        }
        
        for result in js_results:
            for secret in result.secrets:
                finding = secret.to_dict()
                finding['source_file'] = result.url
                findings['secrets'][secret.confidence].append(finding)
            
            for ref in result.internal_refs:
                finding = ref.to_dict()
                finding['source_file'] = result.url
                findings['internal_references'].append(finding)
            
            for sensitive in result.sensitive_data:
                finding = sensitive.to_dict()
                finding['source_file'] = result.url
                findings['sensitive_data'].append(finding)
            
            for endpoint in result.api_endpoints:
                findings['api_endpoints'].append({
                    'endpoint': endpoint,
                    'source_file': result.url
                })
        
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
