import argparse
import json
import sys
import importlib
import time
from pathlib import Path

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
except Exception:
    # fallback if colorama not installed
    class _C:
        RESET = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
    Fore = _C()
    Style = _C()

AVAILABLE_MODULES = {
    "dns": "modules.dns_lookup",
    "whois": "modules.whois_lookup",
    "headers": "modules.headers",
    "portscan": "modules.portscan",
}

def parse_args():
    p = argparse.ArgumentParser(prog="reconx", description="ReconX - mini recon toolkit")
    p.add_argument("--target", "-t", required=True, help="Target domain or IP (e.g. example.com)")
    p.add_argument("--modules", "-m", default="dns,whois,headers,portscan",
                   help="Comma-separated modules to run. Available: " + ",".join(AVAILABLE_MODULES.keys()))
    p.add_argument("--timeout", type=float, default=3.0, help="Timeout (seconds) for network ops (per module)")
    p.add_argument("--output", "-o", help="Write JSON report to file")
    p.add_argument("--top-ports", type=int, default=50, help="# of common ports to scan (portscan module)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--quiet", "-q", action="store_true", help="Minimal console output")
    return p.parse_args()

def pretty_print_section(title, data, no_color=False):
    c_title = Fore.GREEN + title + Style.RESET_ALL if not no_color else title
    print()
    print(c_title)
    print("-" * len(title))
    if isinstance(data, dict):
        for k, v in data.items():
            print(f"{Fore.YELLOW if not no_color else ''}{k}:{Style.RESET_ALL if not no_color else ''} {v}")
    else:
        print(data)

def load_module_by_name(name):
    if name not in AVAILABLE_MODULES:
        raise ValueError(f"Unknown module '{name}'")
    mod_path = AVAILABLE_MODULES[name]
    try:
        return importlib.import_module(mod_path)
    except Exception as e:
        raise ImportError(f"Failed to import module '{name}' ({mod_path}): {e}")

def run_modules(target, module_names, args):
    results = {}
    for name in module_names:
        name = name.strip()
        if not name:
            continue
        try:
            mod = load_module_by_name(name)
        except Exception as e:
            results[name] = {"error": str(e)}
            continue

        run_fn = getattr(mod, "run", None)
        if not callable(run_fn):
            results[name] = {"error": "module missing run(target, options) function"}
            continue

        try:
            start = time.time()
            res = run_fn(target, {"timeout": args.timeout, "top_ports": args.top_ports})
            elapsed = time.time() - start
            # attach metadata
            results[name] = {"elapsed": round(elapsed, 2), "data": res}
        except Exception as e:
            results[name] = {"error": str(e)}
    return results

def main():
    args = parse_args()
    if args.no_color:
        # disable by overriding Fore/Style
        global Fore, Style
        class _C:
            RESET = ''
            GREEN = ''
            YELLOW = ''
            RED = ''
        Fore = _C(); Style = _C()

    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    print(Fore.GREEN + "\n=== ReconX v1.0 ===\n" + Style.RESET_ALL)
    print(f"Target: {args.target}")
    print(f"Modules: {', '.join(modules)}")
    if not args.quiet:
        print(f"Timeout: {args.timeout}s\n")

    results = run_modules(args.target, modules, args)

    # Display results in console
    for mod in modules:
        payload = results.get(mod, {"error": "no result"})
        if "error" in payload:
            pretty_print_section(f"[{mod}] ERROR", payload["error"], no_color=args.no_color)
        else:
            pretty_print_section(f"[{mod}] (elapsed: {payload.get('elapsed', '?')}s)", payload["data"], no_color=args.no_color)

    # optionally write JSON
    if args.output:
        out_path = Path(args.output)
        try:
            with out_path.open("w", encoding="utf-8") as fh:
                json.dump({"target": args.target, "modules": modules, "results": results}, fh, indent=2)
            print(f"\nReport written to {out_path.resolve()}")
        except Exception as e:
            print(Fore.RED + f"Failed to write output file: {e}" + Style.RESET_ALL, file=sys.stderr)

if __name__ == "__main__":
    main()