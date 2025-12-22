#!/usr/bin/env python3
"""
ReconHunter CLI - Professional Bug Bounty Reconnaissance Tool
Modular 3-Phase Architecture: Recon -> Filter JS -> Analyze JS
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init, Fore, Style
init(autoreset=True)

from src.core.config import Config, get_default_config
from src.core.logger import logger, set_verbose, set_silent
from src.core.normalizer import normalize_input
from src.services.datastore import DataStore
from src.pipelines.recon import ReconRunner
from src.pipelines.js_filter import JsFilterRunner
from src.pipelines.js_analysis import JsAnalysisRunner


def print_banner():
    banner = """
""" + Fore.CYAN + """╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   """ + Fore.WHITE + """██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                  """ + Fore.CYAN + """║
║   """ + Fore.WHITE + """██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                  """ + Fore.CYAN + """║
║   """ + Fore.WHITE + """██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                  """ + Fore.CYAN + """║
║   """ + Fore.WHITE + """██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                  """ + Fore.CYAN + """║
║   """ + Fore.WHITE + """██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                  """ + Fore.CYAN + """║
║   """ + Fore.WHITE + """╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                  """ + Fore.CYAN + """║
║                                                                   ║
║   """ + Fore.YELLOW + """██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗        """ + Fore.CYAN + """║
║   """ + Fore.YELLOW + """██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗       """ + Fore.CYAN + """║
║   """ + Fore.YELLOW + """███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝       """ + Fore.CYAN + """║
║   """ + Fore.YELLOW + """██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗       """ + Fore.CYAN + """║
║   """ + Fore.YELLOW + """██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║       """ + Fore.CYAN + """║
║   """ + Fore.YELLOW + """╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝       """ + Fore.CYAN + """║
║                                                                   ║
║   """ + Fore.GREEN + """Modular Bug Bounty Reconnaissance Tool v2.0.0              """ + Fore.CYAN + """║
║   """ + Fore.WHITE + """For authorized security testing only                        """ + Fore.CYAN + """║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL
    
    print(banner, flush=True)


def show_help():
    print(f"""
{Fore.CYAN}Usage:{Style.RESET_ALL}
    python cli.py <command> <target> [options]

{Fore.CYAN}Commands (Modular Pipeline):{Style.RESET_ALL}
    {Fore.GREEN}recon{Style.RESET_ALL}       Phase 1: Collect URLs only (no JS analysis)
    {Fore.GREEN}filter-js{Style.RESET_ALL}   Phase 2: Extract JS URLs from recon data
    {Fore.GREEN}analyze-js{Style.RESET_ALL}  Phase 3: Deep static analysis of JS files
    {Fore.GREEN}pipeline{Style.RESET_ALL}    Run all 3 phases sequentially
    {Fore.GREEN}status{Style.RESET_ALL}      Show status of existing scans

{Fore.CYAN}Legacy Commands:{Style.RESET_ALL}
    scan      Run recon + analysis (original behavior)
    batch     Scan multiple targets from a file
    sources   List available OSINT sources

{Fore.CYAN}Options:{Style.RESET_ALL}
    -o, --output <dir>    Output directory (default: recon_output)
    -i, --input <file>    Input file (URL list for filter-js/analyze-js)
    -v, --verbose         Verbose output
    -s, --silent          Silent mode (minimal output)
    --no-wayback          Disable Wayback Machine
    --no-urlscan          Disable URLScan.io
    --no-alienvault       Disable AlienVault OTX

{Fore.CYAN}Examples (New Modular Workflow):{Style.RESET_ALL}
    {Fore.WHITE}# Phase 1: Collect URLs only{Style.RESET_ALL}
    python cli.py recon example.com -o results

    {Fore.WHITE}# Phase 2: Extract JS URLs from recon data{Style.RESET_ALL}
    python cli.py filter-js example.com -o results

    {Fore.WHITE}# Phase 3: Analyze JS files{Style.RESET_ALL}
    python cli.py analyze-js example.com -o results

    {Fore.WHITE}# Run all phases at once{Style.RESET_ALL}
    python cli.py pipeline example.com -o results

    {Fore.WHITE}# Use custom URL list for filter-js{Style.RESET_ALL}
    python cli.py filter-js example.com -i my_urls.txt

{Fore.CYAN}Examples (Legacy):{Style.RESET_ALL}
    python cli.py scan example.com
    python cli.py batch targets.txt
""")


def parse_args(args):
    options = {
        'output': 'recon_output',
        'input': None,
        'verbose': False,
        'silent': False,
        'wayback': True,
        'urlscan': True,
        'alienvault': True,
    }
    
    positional = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ['-o', '--output']:
            if i + 1 < len(args):
                options['output'] = args[i + 1]
                i += 2
                continue
        elif arg in ['-i', '--input']:
            if i + 1 < len(args):
                options['input'] = args[i + 1]
                i += 2
                continue
        elif arg in ['-v', '--verbose']:
            options['verbose'] = True
        elif arg in ['-s', '--silent']:
            options['silent'] = True
        elif arg == '--no-wayback':
            options['wayback'] = False
        elif arg == '--no-urlscan':
            options['urlscan'] = False
        elif arg == '--no-alienvault':
            options['alienvault'] = False
        elif arg in ['-h', '--help']:
            return 'help', [], options
        elif not arg.startswith('-'):
            positional.append(arg)
        i += 1
    
    command = positional[0] if positional else None
    targets = positional[1:] if len(positional) > 1 else []
    
    return command, targets, options


def run_recon(target, options):
    """Phase 1: Reconnaissance - URL collection only"""
    print_banner()
    
    if options['verbose']:
        set_verbose(True)
    elif options['silent']:
        set_silent(True)
    
    config = get_default_config()
    config.output_dir = options['output']
    config.wayback.enabled = options['wayback']
    config.urlscan.enabled = options['urlscan']
    config.alienvault.enabled = options['alienvault']
    
    if not options['silent']:
        print(f"\n{Fore.CYAN}[Phase 1] RECONNAISSANCE MODE{Style.RESET_ALL}")
        print(f"  Target: {target}")
        print(f"  Output: {options['output']}")
        print(f"  {Fore.YELLOW}Collecting URLs only - no JS analysis{Style.RESET_ALL}\n")
    
    try:
        runner = ReconRunner(config, silent_mode=options['silent'])
        result = runner.run_sync(target)
        
        if not options['silent']:
            print(f"\n{Fore.GREEN}[+] Reconnaissance complete!{Style.RESET_ALL}")
            print(f"  Total URLs: {result.total_urls}")
            print(f"  Domains: {len(result.urls_by_domain)}")
            print(f"  Sources: {', '.join(result.sources_used)}")
            print(f"\n  {Fore.CYAN}Next step: python cli.py filter-js {target}{Style.RESET_ALL}")
        
        return result
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Recon failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_filter_js(target, options):
    """Phase 2: Extract and categorize JS URLs"""
    print_banner()
    
    if options['verbose']:
        set_verbose(True)
    elif options['silent']:
        set_silent(True)
    
    if not options['silent']:
        print(f"\n{Fore.CYAN}[Phase 2] JAVASCRIPT URL FILTERING{Style.RESET_ALL}")
        print(f"  Target: {target}")
        if options['input']:
            print(f"  Input: {options['input']}")
        print(f"  {Fore.YELLOW}Extracting JS URLs from recon data{Style.RESET_ALL}\n")
    
    try:
        runner = JsFilterRunner(silent_mode=options['silent'], output_dir=options['output'])
        
        if options['input']:
            result = runner.run_from_file(target, options['input'])
        else:
            result = runner.run(target)
        
        if not options['silent']:
            print(f"\n{Fore.GREEN}[+] JS URL filtering complete!{Style.RESET_ALL}")
            print(f"  Total JS URLs: {result.total_js_urls}")
            print(f"  Internal: {len(result.internal_js)}")
            print(f"  External: {len(result.external_js)}")
            print(f"\n  {Fore.CYAN}Next step: python cli.py analyze-js {target}{Style.RESET_ALL}")
        
        return result
        
    except Exception as e:
        logger.error(f"JS filtering failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_analyze_js(target, options):
    """Phase 3: Deep static analysis of JS files"""
    print_banner()
    
    if options['verbose']:
        set_verbose(True)
    elif options['silent']:
        set_silent(True)
    
    if not options['silent']:
        print(f"\n{Fore.CYAN}[Phase 3] JAVASCRIPT ANALYSIS{Style.RESET_ALL}")
        print(f"  Target: {target}")
        print(f"  {Fore.YELLOW}Deep static analysis with confidence scoring{Style.RESET_ALL}\n")
    
    try:
        runner = JsAnalysisRunner(silent_mode=options['silent'], output_dir=options['output'])
        result = runner.run(target)
        
        if not options['silent']:
            print(f"\n{Fore.GREEN}[+] JS analysis complete!{Style.RESET_ALL}")
            print(f"  Files analyzed: {result.total_files}")
            print(f"  Total findings: {result.total_findings}")
            
            if result.findings_by_confidence:
                print(f"\n  {Fore.CYAN}Findings by confidence:{Style.RESET_ALL}")
                for level, count in result.findings_by_confidence.items():
                    color = Fore.RED if level == 'high' else Fore.YELLOW if level == 'medium' else Fore.WHITE
                    print(f"    {color}{level.upper()}: {count}{Style.RESET_ALL}")
            
            if result.findings_by_category:
                print(f"\n  {Fore.CYAN}Findings by category:{Style.RESET_ALL}")
                for cat, count in sorted(result.findings_by_category.items(), key=lambda x: -x[1])[:5]:
                    print(f"    {cat}: {count}")
            
            print(f"\n  {Fore.CYAN}Reports saved to: {options['output']}{Style.RESET_ALL}")
        
        return result
        
    except Exception as e:
        logger.error(f"JS analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_pipeline(target, options):
    """Run all three phases sequentially"""
    print_banner()
    
    if not options['silent']:
        print(f"\n{Fore.GREEN}[FULL PIPELINE] Running all 3 phases{Style.RESET_ALL}")
        print(f"  Target: {target}")
        print(f"  Output: {options['output']}\n")
    
    recon_result = run_recon(target, options)
    
    filter_result = run_filter_js(target, options)
    
    analysis_result = run_analyze_js(target, options)
    
    if not options['silent']:
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] PIPELINE COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"\n  {Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"    URLs collected: {recon_result.total_urls}")
        print(f"    JS files found: {filter_result.total_js_urls}")
        print(f"    Findings: {analysis_result.total_findings}")
        print(f"\n  {Fore.CYAN}Results saved to: {options['output']}{Style.RESET_ALL}")
    
    return analysis_result


def show_status(options):
    """Show status of existing scans"""
    print_banner()
    
    datastore = DataStore(options['output'])
    targets = datastore.get_all_targets()
    
    if not targets:
        print(f"\n{Fore.YELLOW}No scans found in {options['output']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}Existing Scans in {options['output']}:{Style.RESET_ALL}\n")
    
    for target in targets:
        status = datastore.get_target_status(target)
        
        recon_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status['has_recon'] else f"{Fore.RED}✗{Style.RESET_ALL}"
        js_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status['has_js_urls'] else f"{Fore.RED}✗{Style.RESET_ALL}"
        findings_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status['has_findings'] else f"{Fore.RED}✗{Style.RESET_ALL}"
        
        print(f"  {Fore.WHITE}{target}{Style.RESET_ALL}")
        print(f"    [1] Recon: {recon_icon}  [2] JS URLs: {js_icon}  [3] Findings: {findings_icon}")
        print()


def show_sources():
    print_banner()
    
    sources_info = [
        ("Wayback Machine", "Historical URL archive from web.archive.org", "No API key required"),
        ("Common Crawl", "World's largest web crawl index", "No API key required"),
        ("URLScan.io", "URL scanning and analysis", "API key optional (higher rate limits)"),
        ("AlienVault OTX", "Threat intelligence platform", "API key optional"),
        ("Live Discovery", "robots.txt, sitemap.xml, multi-page crawling", "No API key required"),
        ("Google", "Safe dorking with site: operator", "No API key required"),
        ("Bing", "Search engine dorking", "No API key required"),
        ("DuckDuckGo", "Privacy-focused search", "No API key required"),
    ]
    
    print(f"\n{Fore.CYAN}Available OSINT Sources:{Style.RESET_ALL}\n")
    
    for name, desc, auth in sources_info:
        print(f"  {Fore.GREEN}{name}{Style.RESET_ALL}")
        print(f"    {desc}")
        print(f"    {Fore.YELLOW}Auth: {auth}{Style.RESET_ALL}\n")


def run_legacy_scan(target, options):
    """Legacy scan command - runs recon + analysis"""
    from src.recon_engine import ReconEngine
    
    print_banner()
    
    if options['verbose']:
        set_verbose(True)
    elif options['silent']:
        set_silent(True)
    
    config = get_default_config()
    config.output_dir = options['output']
    config.wayback.enabled = options['wayback']
    config.urlscan.enabled = options['urlscan']
    config.alienvault.enabled = options['alienvault']
    config.js_analysis = True
    
    engine = ReconEngine(config, silent_mode=options['silent'])
    
    if not options['silent']:
        logger.info(f"Target: {target}")
        logger.info(f"Output directory: {options['output']}")
    
    try:
        asyncio.run(engine.run(target, analyze_js=True))
        html_path = engine.export_html(target, options['output'])
        json_dir = engine.export_json(target, options['output'])
        
        if not options['silent']:
            logger.info(f"HTML report: {html_path}")
            logger.info(f"JSON exports: {json_dir}")
        
        print(f"\n{Fore.GREEN}[+] Reconnaissance complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    View results in: {options['output']}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)


def main():
    args = sys.argv[1:]
    
    if not args:
        print_banner()
        show_help()
        return
    
    command, targets, options = parse_args(args)
    
    if command == 'help' or command == '-h' or command == '--help':
        print_banner()
        show_help()
    elif command == 'recon':
        if not targets:
            print(f"{Fore.RED}[-] Error: No target specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py recon <target>")
            sys.exit(1)
        run_recon(targets[0], options)
    elif command == 'filter-js':
        if not targets:
            print(f"{Fore.RED}[-] Error: No target specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py filter-js <target>")
            sys.exit(1)
        run_filter_js(targets[0], options)
    elif command == 'analyze-js':
        if not targets:
            print(f"{Fore.RED}[-] Error: No target specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py analyze-js <target>")
            sys.exit(1)
        run_analyze_js(targets[0], options)
    elif command == 'pipeline':
        if not targets:
            print(f"{Fore.RED}[-] Error: No target specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py pipeline <target>")
            sys.exit(1)
        run_pipeline(targets[0], options)
    elif command == 'status':
        show_status(options)
    elif command == 'scan':
        if not targets:
            print(f"{Fore.RED}[-] Error: No target specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py scan <target>")
            sys.exit(1)
        run_legacy_scan(targets[0], options)
    elif command == 'batch':
        if not targets:
            print(f"{Fore.RED}[-] Error: No file specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py batch <file>")
            sys.exit(1)
        print(f"{Fore.YELLOW}Batch mode - using legacy scan for each target{Style.RESET_ALL}")
        with open(targets[0], 'r') as f:
            batch_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        for t in batch_targets:
            run_legacy_scan(t, options)
    elif command == 'sources':
        show_sources()
    else:
        print(f"{Fore.RED}[-] Unknown command: {command}{Style.RESET_ALL}")
        show_help()


if __name__ == '__main__':
    main()
