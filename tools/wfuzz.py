import subprocess
import json
from typing import Optional, Dict, Any


def run_wfuzz(
    url: str,
    wordlist: str,
    show_code: Optional[str] = "200,302,403,500",
) -> str:
    """Run wfuzz to fuzz web application endpoints.
    
    Args:
        url: Target URL with FUZZ keyword (e.g., "http://example.com/FUZZ")
        wordlist: Path to wordlist file
        hide_code: HTTP status code to hide (e.g., "404")
    
    Returns:
        Dict[str, Any]: Dictionary containing fuzzing results
    """
    try:
    # Build the command
        cmd = ["wfuzz", "-w", wordlist, "--sc", show_code, "-o", "json", url]

        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Parse the output
        import re
        findings = []
        # Regex to match wfuzz result lines (payload, code, url)
        pattern = re.compile(r'\{"chars":.*?"code": (\d+),.*?"payload": "(.*?)",.*?"url": "(.*?)".*?\}')
        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match:
                findings.append({
                    "status": int(match.group(1)),
                    "payload": match.group(2),
                    "url": match.group(3)
                })
        return json.dumps({
            "success": True,
            "url": url,
            "results": findings,
            "total": len(findings)
        })

    except subprocess.CalledProcessError as e:
        return json.dumps({
            "success": False,
            "error": str(e),
            "stderr": e.stderr
        })
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })