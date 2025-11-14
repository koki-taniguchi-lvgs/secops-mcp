import subprocess
import json
from typing import Optional, Dict, Any


def run_ffuf(
    url: str,
    wordlist: str,
    filter_code: Optional[str] = "404",
) -> str:
    """Run ffuf to fuzz web application endpoints.
    
    Args:
        url: Target URL with FUZZ keyword (e.g., "http://example.com/FUZZ")
        wordlist: Path to wordlist file
        filter_code: HTTP status code to filter out (e.g., "404")
    
    Returns:
        Dict[str, Any]: Dictionary containing fuzzing results
    """
    try:
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmpfile:
            output_path = tmpfile.name
        cmd = ["ffuf", "-w", wordlist, "-u", url, "-of", "json", "-o", output_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            with open(output_path, "r") as f:
                data = json.load(f)
            os.remove(output_path)
            findings = []
            for entry in data.get("results", []):
                findings.append({
                    "status": entry.get("status"),
                    "path": entry.get("input", {}).get("FUZZ"),
                    "url": entry.get("url"),
                    "length": entry.get("length"),
                    "words": entry.get("words"),
                    "lines": entry.get("lines")
                })
            return json.dumps({
                "success": True,
                "url": url,
                "results": findings,
                "total": len(findings)
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": f"Failed to parse ffuf JSON output: {str(e)}",
                "raw_output": result.stdout
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