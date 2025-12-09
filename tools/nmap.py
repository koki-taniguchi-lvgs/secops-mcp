import subprocess
import json
from typing import List, Optional, Dict, Any
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


def run_nmap(
    target: str,
    ports: Optional[str] = None,
    options: Optional[List[str]] = None,
) -> str:
    """Run an Nmap network scan on the specified target.
    
    Args:
        target: The target IP or hostname to scan
        ports: Specific ports to scan (e.g., "22,80,443")
        options: Additional Nmap options (e.g., ["-sV", "-A"])
    
    Returns:
        str: JSON string containing scan results
    """
    try:
        # Build the command with verbosity and speed
        cmd = ["nmap", "-v", "-T5"]
        # Only add -p if ports are specified; otherwise, scan top 1000 ports (nmap default)
        if ports:
            cmd.extend(["-p", ports])
        if options:
            cmd.extend(options)
        # Output in XML format to stdout
        cmd.extend(["-oX", "-", target])

        logger.info(f"[nmap] Executing command: {' '.join(cmd)}")
        logger.info(f"[nmap] Target: {target}")

        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        logger.info(f"[nmap] Command completed successfully")
        logger.info(f"[nmap] Output length: {len(result.stdout)} bytes")
        if result.stderr:
            logger.info(f"[nmap] stderr: {result.stderr}")

        # Parse the output
        return json.dumps({
            "success": True,
            "target": target,
            "ports": ports if ports else "top-1000",
            "results": {
                "xml_output": result.stdout,
                "options": options or []
            }
        })

    except subprocess.CalledProcessError as e:
        logger.error(f"[nmap] Command failed with return code {e.returncode}")
        logger.error(f"[nmap] stderr: {e.stderr}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "stderr": e.stderr
        })
    except Exception as e:
        logger.error(f"[nmap] Exception: {str(e)}")
        return json.dumps({
            "success": False,
            "error": str(e)
        })