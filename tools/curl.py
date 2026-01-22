import subprocess
import json
from typing import List, Optional, Dict, Any

def run_curl(
    url: str,
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Run curl to transfer data.
    
    Args:
        url: The URL to interact with
        options: Additional curl options (e.g., ["-X", "POST", "-d", "data"])
        rate_limit: Maximum requests per second (optional, not natively supported by curl but added for schema consistency)
    
    Returns:
        str: JSON string containing command results
    """
    try:
        # Defaults: -s for silent (no progress bar), -i for headers
        cmd = ["curl", "-s", "-i"]
        
        # Note: rate_limit is not natively supported by a single curl command 
        # for req/s, but we keep it in the signature for agent guidance.
        
        if options:
            cmd.extend(options)
            
        cmd.append(url)
            
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        
        # Save results
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/curl_latest.txt", "w") as f:
            f.write(result.stdout)
            
        # Separate headers and body for intelligence
        # Use more robust splitting for headers and body
        if "\r\n\r\n" in result.stdout:
            parts = result.stdout.split("\r\n\r\n", 1)
        elif "\n\n" in result.stdout:
            parts = result.stdout.split("\n\n", 1)
        else:
            parts = [result.stdout]
            
        headers = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        
        # If the split failed and headers is massive, it might be because there were no headers
        # or the delimiter was missing. In that case, treat it all as body.
        if not body and len(headers) > 2000 and "HTTP/" not in headers[:100]:
            body = headers
            headers = "No headers found or split failed."

        # Return a summarized version to the LLM
        max_body_preview = 1000
        max_headers_limit = 2000
        
        body_preview = body[:max_body_preview]
        headers_truncated = headers[:max_headers_limit]
        
        is_body_truncated = len(body) > max_body_preview
        is_headers_truncated = len(headers) > max_headers_limit

        return json.dumps({
            "success": result.returncode == 0,
            "url": url,
            "headers": headers_truncated + ("\n... [HEADERS TRUNCATED] ..." if is_headers_truncated else ""),
            "body_preview": body_preview + ("\n... [BODY TRUNCATED] ..." if is_body_truncated else ""),
            "body_size_bytes": len(body),
            "full_output_path": "/tmp/secops_results/curl_latest.txt",
            "returncode": result.returncode,
            "stderr": result.stderr
        })
        
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        })
