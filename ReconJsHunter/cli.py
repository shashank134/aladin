#!/usr/bin/env python3
"""
ReconHunter CLI - Professional Bug Bounty Reconnaissance Tool
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
from src.recon_engine import ReconEngine


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
║   """ + Fore.GREEN + """Professional Bug Bounty Reconnaissance Tool v1.0.0          """ + Fore.CYAN + """║
║   """ + Fore.WHITE + """For authorized security testing only                        """ + Fore.CYAN + """║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL
    
    print(banner, flush=True)


def show_help():
    print(f"""
{Fore.CYAN}Usage:{Style.RESET_ALL}
    python cli.py scan <target> [options]
    python cli.py batch <file> [options]
    python cli.py sources

{Fore.CYAN}Commands:{Style.RESET_ALL}
    scan     Scan a target domain for reconnaissance
    batch    Scan multiple targets from a file
    sources  List available OSINT sources

{Fore.CYAN}Options:{Style.RESET_ALL}
    -o, --output <dir>    Output directory (default: recon_output)
    --no-js               Skip JavaScript analysis
    -v, --verbose         Verbose output
    -s, --silent          Silent mode (minimal output)
    --json-only           Export JSON only
    --html-only           Export HTML only
    --no-wayback          Disable Wayback Machine
    --no-urlscan          Disable URLScan.io
    --no-alienvault       Disable AlienVault OTX

{Fore.CYAN}Examples:{Style.RESET_ALL}
    python cli.py scan example.com
    python cli.py scan example.com -o results --silent
    python cli.py batch targets.txt -v
""")


def parse_args(args):
    options = {
        'output': 'recon_output',
        'no_js': False,
        'verbose': False,
        'silent': False,
        'json_only': False,
        'html_only': False,
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
        elif arg == '--no-js':
            options['no_js'] = True
        elif arg in ['-v', '--verbose']:
            options['verbose'] = True
        elif arg in ['-s', '--silent']:
            options['silent'] = True
        elif arg == '--json-only':
            options['json_only'] = True
        elif arg == '--html-only':
            options['html_only'] = True
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


def run_scan(target, options):
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
    config.js_analysis = not options['no_js']
    
    if not options['silent']:
        logger.info(f"Target: {target}")
        logger.info(f"Output directory: {options['output']}")
    
    engine = ReconEngine(config)
    
    try:
        asyncio.run(engine.run(target, analyze_js=not options['no_js']))
        
        if not options['json_only']:
            html_path = engine.export_html(target, options['output'])
            if not options['silent']:
                logger.info(f"HTML report: {html_path}")
        
        if not options['html_only']:
            json_dir = engine.export_json(target, options['output'])
            if not options['silent']:
                logger.info(f"JSON exports: {json_dir}")
        
        print(f"\n{Fore.GREEN}[+] Reconnaissance complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    View results in: {options['output']}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)


def run_batch(file_path, options):
    print_banner()
    
    if options['verbose']:
        set_verbose(True)
    elif options['silent']:
        set_silent(True)
    
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[-] File not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)
    
    with open(file_path, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not targets:
        print(f"{Fore.RED}[-] No valid targets found in file{Style.RESET_ALL}")
        sys.exit(1)
    
    if not options['silent']:
        logger.info(f"Loaded {len(targets)} targets from {file_path}")
    
    config = get_default_config()
    config.output_dir = options['output']
    config.js_analysis = not options['no_js']
    config.wayback.enabled = options['wayback']
    config.urlscan.enabled = options['urlscan']
    config.alienvault.enabled = options['alienvault']
    
    for i, target in enumerate(targets, 1):
        if not options['silent']:
            print(f"\n{'='*60}")
            print(f"Processing target {i}/{len(targets)}: {target}")
            print(f"{'='*60}\n")
        
        engine = ReconEngine(config)
        
        try:
            asyncio.run(engine.run(target, analyze_js=not options['no_js']))
            engine.export_html(target, options['output'])
            engine.export_json(target, options['output'])
        except Exception as e:
            logger.error(f"Failed to scan {target}: {e}")
            continue
    
    print(f"\n{Fore.GREEN}[+] Batch scan complete!{Style.RESET_ALL}")


def show_sources():
    print_banner()
    
    sources_info = [
        ("Wayback Machine", "Historical URL archive from web.archive.org", "No API key required"),
        ("URLScan.io", "URL scanning and analysis", "API key optional (higher rate limits)"),
        ("AlienVault OTX", "Threat intelligence platform", "API key optional"),
    ]
    
    print(f"\n{Fore.CYAN}Available OSINT Sources:{Style.RESET_ALL}\n")
    
    for name, desc, auth in sources_info:
        print(f"  {Fore.GREEN}{name}{Style.RESET_ALL}")
        print(f"    {desc}")
        print(f"    {Fore.YELLOW}Auth: {auth}{Style.RESET_ALL}\n")


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
    elif command == 'scan':
        if not targets:
            print(f"{Fore.RED}[-] Error: No target specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py scan <target>")
            sys.exit(1)
        run_scan(targets[0], options)
    elif command == 'batch':
        if not targets:
            print(f"{Fore.RED}[-] Error: No file specified{Style.RESET_ALL}")
            print(f"Usage: python cli.py batch <file>")
            sys.exit(1)
        run_batch(targets[0], options)
    elif command == 'sources':
        show_sources()
    else:
        print(f"{Fore.RED}[-] Unknown command: {command}{Style.RESET_ALL}")
        show_help()


if __name__ == '__main__':
    main()
