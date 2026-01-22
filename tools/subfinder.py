import subprocess
import json
from typing import Optional, Dict, Any, List
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


def run_subfinder(
    domain: str,
    output_format: Optional[str] = "json",
    options: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
) -> str:
    """Run subfinder to enumerate subdomains.
    
    Args:
        domain: Target domain to enumerate
        output_format: Output format (text or json)
        options: Additional subfinder options (e.g., ["-all", "-recursive"])
        rate_limit: Maximum requests per second (optional)
    
    Returns:
        str: JSON string containing enumeration results
    """
    try:
        from typing import List
        # Build the command
        cmd = ["subfinder", "-d", domain, "-silent"]
        if output_format == "json":
            cmd.append("-json")
        if rate_limit: cmd.extend(["-rl", str(rate_limit)])
        if options: cmd.extend(options)
        
        logger.info(f"[subfinder] Executing command: {' '.join(cmd)}")
        
        # Run the command with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        data = []
        if process.stdout:
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    obj = json.loads(clean_line)
                    data.append(obj)
                    if "host" in obj:
                        print(f"🔍 [subfinder] Found: {obj['host']}", flush=True)
                except json.JSONDecodeError:
                    continue
        
        _, stderr = process.communicate()
        return_code = process.wait()
        
        if return_code != 0:
            logger.error(f"[subfinder] Command failed with return code {return_code}")
            return json.dumps({
                "success": False,
                "error": f"Command failed with return code {return_code}",
                "stderr": stderr
            })

        logger.info(f"[subfinder] Command completed successfully")
        logger.info(f"[subfinder] Total found: {len(data)}")
        
        # Save all results to storage
        import os
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/subfinder_latest.json", "w") as f:
            json.dump(data, f, indent=2)

        # Return a summary to avoid context overflow
        limit = 100
        summary_data = data[:limit]
        
        return json.dumps({
            "success": True,
            "domain": domain,
            "summary": summary_data,
            "total_found": len(data),
            "is_truncated": len(data) > limit,
            "note": "Use grep_stored_results('subfinder', pattern) if you need to search the full list."
        })
    except Exception as e:
        logger.error(f"[subfinder] Exception: {str(e)}")
        return json.dumps({
            "success": False,
            "error": str(e)
        })