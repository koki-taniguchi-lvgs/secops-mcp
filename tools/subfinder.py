import subprocess
import json
from typing import Optional, Dict, Any
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
) -> str:
    """Run subfinder to enumerate subdomains.
    
    Args:
        domain: Target domain to enumerate
        output_format: Output format (text or json)
    
    Returns:
        str: JSON string containing enumeration results
    """
    try:
        # Build the command
        cmd = ["subfinder", "-d", domain, "-json"]
        
        logger.info(f"[subfinder] Executing command: {' '.join(cmd)}")
        logger.info(f"[subfinder] Domain: {domain}")
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        logger.info(f"[subfinder] Command completed successfully")
        logger.info(f"[subfinder] Output lines: {len(result.stdout.splitlines())}")
        if result.stderr:
            logger.info(f"[subfinder] stderr: {result.stderr}")
        
        # Parse line-delimited JSON output
        try:
            lines = [line for line in result.stdout.splitlines() if line.strip()]
            data = [json.loads(line) for line in lines]
            
            # Save all results to storage
            import os
            os.makedirs("/tmp/secops_results", exist_ok=True)
            with open("/tmp/secops_results/subfinder_latest.json", "w") as f:
                json.dump(data, f)

            # Return a summary to avoid context overflow
            limit = 100
            summary_data = data[:limit]
            
            return json.dumps({
                "success": True,
                "domain": domain,
                "summary": summary_data,
                "total_found": len(data),
                "is_truncated": len(data) > limit,
                "note": "Use fetch_all_subdomains() if you need the full list."
            })
        except json.JSONDecodeError:
            return json.dumps({
                "success": False,
                "error": "Failed to parse JSON output",
                "raw_output": result.stdout
            })
        
    except subprocess.CalledProcessError as e:
        logger.error(f"[subfinder] Command failed with return code {e.returncode}")
        logger.error(f"[subfinder] stderr: {e.stderr}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "stderr": e.stderr
        })
    except Exception as e:
        logger.error(f"[subfinder] Exception: {str(e)}")
        return json.dumps({
            "success": False,
            "error": str(e)
        })