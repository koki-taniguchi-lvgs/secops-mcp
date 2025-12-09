import subprocess
import requests
import json
import socket
from typing import Optional
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


def run_ipinfo(ip: Optional[str] = None) -> str:
    """Get IP information using ipinfo.io
    
    Args:
        ip: Optional IP address or hostname to lookup. If not provided, uses the current IP.
    
    Returns:
        str: IP information in JSON format
    """
    logger.info(f"[ipinfo] Received target: {ip}")
    
    try:
        # If an IP/hostname is provided, resolve it to an IP if needed
        if ip:
            # Check if it's already an IP address
            try:
                socket.inet_aton(ip)
                # It's already an IP
                target_ip = ip
                logger.info(f"[ipinfo] Target is already an IP address: {target_ip}")
            except socket.error:
                # It's a hostname, resolve it
                logger.info(f"[ipinfo] Resolving hostname: {ip}")
                target_ip = socket.gethostbyname(ip)
                logger.info(f"[ipinfo] Resolved to IP: {target_ip}")
            
            url = f"https://ipinfo.io/{target_ip}/json"
        else:
            url = "https://ipinfo.io/json"
        
        logger.info(f"[ipinfo] Calling ipinfo.io API: {url}")
        response = requests.get(url)
        
        if response.status_code == 200:
            logger.info(f"[ipinfo] API call successful, received {len(response.text)} bytes")
            return json.dumps(response.json(), indent=2)
        else:
            logger.error(f"[ipinfo] API error: status code {response.status_code}")
            return f"Error: Received status code {response.status_code} from ipinfo.io"
    except Exception as e:
        logger.error(f"[ipinfo] Exception: {str(e)}")
        return f"Error getting IP information: {str(e)}" 
