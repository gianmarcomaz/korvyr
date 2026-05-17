import json
import sys
import re
from pathlib import Path
from tqdm import tqdm

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

def test_regexes(sock_regex, shell_regex):
    mal_dir = Path("data/raw/malicious/npm")
    ben_dir = Path("data/raw/benign")
    
    mal_pkgs = []
    for d in mal_dir.iterdir():
        if len(mal_pkgs) >= 300: break
        if "node_modules" in d.parts: continue
        pkg_paths = list(d.rglob("package.json"))
        for p in pkg_paths:
            if "node_modules" in p.parts: continue
            mal_pkgs.append(p.parent)
            if len(mal_pkgs) >= 300: break

    ben_pkgs = []
    for p in ben_dir.rglob("package.json"):
        if "node_modules" in p.parts: continue
        ben_pkgs.append(p.parent)
        if len(ben_pkgs) >= 300: break

    mal_count = 0
    ben_count = 0
    ben_fps = []
    
    sock_re = re.compile(sock_regex)
    shell_re = re.compile(shell_regex)
    pipe_re = re.compile(r"\.pipe\s*\(")
    
    # Process malicious
    for pkg_path in mal_pkgs:
        sources = _load_js_sources(pkg_path)
        hit = False
        for fpath, code in sources.items():
            code = normalize(code)
            sock_matches = list(sock_re.finditer(code))
            shell_matches = list(shell_re.finditer(code))
            if not sock_matches or not shell_matches: continue
            
            has_pipe = pipe_re.search(code) is not None
            has_stream_redir = ("stdin" in code) and ("stdout" in code or "stderr" in code)
            
            lines = code.split("\n")
            sock_lines = set([_find_line(code, sm.start()) for sm in sock_matches])
            shell_lines = set([_find_line(code, shm.start()) for shm in shell_matches])
            
            within_30 = False
            for sl in sock_lines:
                for shl in shell_lines:
                    if abs(sl - shl) <= 30:
                        within_30 = True
                        break
                if within_30: break
                
            if within_30 or has_pipe or has_stream_redir:
                hit = True
                break
        if hit: mal_count += 1

    # Process benign
    for pkg_path in ben_pkgs:
        sources = _load_js_sources(pkg_path)
        hit = False
        for fpath, code in sources.items():
            code = normalize(code)
            sock_matches = list(sock_re.finditer(code))
            shell_matches = list(shell_re.finditer(code))
            if not sock_matches or not shell_matches: continue
            
            has_pipe = pipe_re.search(code) is not None
            has_stream_redir = ("stdin" in code) and ("stdout" in code or "stderr" in code)
            
            lines = code.split("\n")
            sock_lines = set([_find_line(code, sm.start()) for sm in sock_matches])
            shell_lines = set([_find_line(code, shm.start()) for shm in shell_matches])
            
            within_30 = False
            for sl in sock_lines:
                for shl in shell_lines:
                    if abs(sl - shl) <= 30:
                        within_30 = True
                        break
                if within_30: break
                
            if within_30 or has_pipe or has_stream_redir:
                hit = True
                break
        if hit: 
            ben_count += 1
            ben_fps.append(pkg_path.parent.name)
            
    print(f"Sock: {sock_regex}")
    print(f"Shell: {shell_regex}")
    print(f"Malicious: {mal_count}, Benign: {ben_count}")
    if ben_fps: print(f"Benign FPs: {ben_fps}")
    print("-" * 40)

if __name__ == "__main__":
    test_regexes(
        r"(net\.Socket|net\.createConnection|net\.connect|new\s+Socket|dgram\.createSocket)",
        r"(child_process\.exec|child_process\.spawn|child_process\.execSync|/bin/sh|/bin/bash|cmd\.exe|powershell\.exe)"
    )
    test_regexes(
        r"(net\.Socket|net\.createConnection|net\.connect|new\s+Socket|dgram\.createSocket|\bnet\b)",
        r"(child_process|/bin/sh|/bin/bash|cmd\.exe|powershell|\bspawn\b|\bexec\b)"
    )
    test_regexes(
        r"(net\.Socket|net\.createConnection|net\.connect|new\s+Socket|dgram\.createSocket)",
        r"(child_process|/bin/sh|/bin/bash|cmd\.exe|powershell|\bspawn\b|\bexec\b)"
    )
    test_regexes(
        r"(net\.Socket|net\.createConnection|net\.connect|new\s+Socket|dgram\.createSocket|\bnet\b)",
        r"(child_process|/bin/sh|/bin/bash|cmd\.exe|powershell|\bspawn\b)"
    )
