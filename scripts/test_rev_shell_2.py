import json
import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from supplyguard.scanner.rules_engine import _load_js_sources, _find_line

_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")
_OCTAL_ESCAPE = re.compile(r"\\[0-7]{1,3}")

def normalize(code: str) -> str:
    code = _HEX_ESCAPE.sub("?", code)
    code = _UNICODE_ESCAPE.sub("?", code)
    code = _OCTAL_ESCAPE.sub("?", code)
    return code

def main():
    mal_dir = Path("data/raw/malicious/npm")
    
    mal_pkgs = []
    for d in mal_dir.iterdir():
        if len(mal_pkgs) >= 300: break
        if "node_modules" in d.parts: continue
        pkg_paths = list(d.rglob("package.json"))
        for p in pkg_paths:
            if "node_modules" in p.parts: continue
            mal_pkgs.append(p.parent)
            if len(mal_pkgs) >= 300: break

    sock_regex = r"(net\.Socket|net\.createConnection|net\.connect|new\s+Socket|dgram\.createSocket|\bnet\b)"
    shell_regex = r"(child_process|/bin/sh|/bin/bash|cmd\.exe|powershell|\bspawn\b)"
    sock_re = re.compile(sock_regex)
    shell_re = re.compile(shell_regex)
    pipe_re = re.compile(r"\.pipe\s*\(")
    
    mal_count = 0
    
    for pkg_path in mal_pkgs:
        sources = _load_js_sources(pkg_path)
        hit = False
        for fpath, code in sources.items():
            code = normalize(code)
            if not sock_re.search(code) or not shell_re.search(code): continue
            has_pipe = pipe_re.search(code) is not None
            has_stream_redir = ("stdin" in code) and ("stdout" in code or "stderr" in code)
            
            sock_matches = list(sock_re.finditer(code))
            shell_matches = list(shell_re.finditer(code))
            sock_lines = set([_find_line(code, sm.start()) for sm in sock_matches])
            shell_lines = set([_find_line(code, shm.start()) for shm in shell_matches])
            within_30 = False
            for sl in sock_lines:
                for shl in shell_lines:
                    if abs(sl - shl) <= 30:
                        within_30 = True
                        break
                if within_30: break
                
            if within_30 and (has_pipe or has_stream_redir):
                hit = True
                break
        if hit: mal_count += 1
        
    print(f"Malicious requiring BOTH within_30 AND pipe/redir: {mal_count}")

if __name__ == "__main__":
    main()
