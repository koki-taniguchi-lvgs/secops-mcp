import subprocess
import json
from typing import Optional, Dict, Any, List


def run_tlsx(host: str, port: Optional[int] = 443, options: Optional[List[str]] = None, rate_limit: Optional[int] = None) -> str:
    """
    Run tlsx to analyze TLS configurations.
    
    Args:
        host: Target hostname or IP address
        port: Target port (default: 443)
        options: Additional tlsx options (e.g., ["-ex", "-san"])
        rate_limit: Maximum requests per second (optional)
    
    Returns:
        str: JSON string containing TLS analysis results
    """
    try:
        # Build the command
        cmd = ["tlsx", "-host", host, "-port", str(port), "-json"]
        if rate_limit:
            # tlsx uses delay, not rate limit. Calculate delay (e.g. 20 req/s -> 0.05s)
            delay = 1.0 / rate_limit
            cmd.extend(["--delay", f"{delay}s"])
        if options: cmd.extend(options)
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the output
        try:
            data = json.loads(result.stdout)
            return json.dumps({
                "success": True,
                "host": host,
                "port": port,
                "results": data
            })
        except json.JSONDecodeError:
            return json.dumps({
                "success": False,
                "error": "Failed to parse JSON output",
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