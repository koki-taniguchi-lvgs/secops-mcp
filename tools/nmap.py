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
    rate_limit: Optional[int] = None,
) -> str:
    """Run an Nmap network scan on the specified target.
    
    Args:
        target: The target IP or hostname to scan
        ports: Specific ports to scan (e.g., "22,80,443")
        options: Additional Nmap options (e.g., ["-sV", "-A"])
        rate_limit: Maximum requests per second (optional)
    
    Returns:
        str: JSON string containing scan results
    """
    import tempfile
    import os

    # Create a temporary file for XML output
    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
    os.close(xml_fd)

    try:
        # Build the command with extra verbosity and status updates
        # Verbosity level 2 (-vv) is used to ensure open ports are logged as discovered.
        cmd = ["nmap", "-vv", "-T5"]
        # Only add -p if ports are specified; otherwise, scan top 1000 ports (nmap default)
        if ports:
            cmd.extend(["-p", ports])
        if rate_limit:
            cmd.extend(["--max-rate", str(rate_limit)])
        if options:
            cmd.extend(options)
        
        # We explicitly add --stats-every at the end of the arguments to override any defaults.
        # Nmap's progress updates often use \r; we ensure these are handled in the logging loop.
        cmd.extend(["--stats-every", "10s"])
        
        # Output in XML format to the temporary file
        cmd.extend(["-oX", xml_path, target])

        logger.info(f"[nmap] Executing command: {' '.join(cmd)}")
        
        # Run the command with streaming output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        full_output = []
        if process.stdout:
            # We want to read byte-by-byte or small chunks to catch \r updates
            # but for simplicity in Python text-mode, we can use a loop that handles both \r and \n.
            # However, nmap redirected to a pipe usually uses \n for --stats-every.
            for line in process.stdout:
                full_output.append(line)
                # handle lines separated by \r within the line
                for subline in line.replace('\r', '\n').split('\n'):
                    clean_line = subline.strip()
                    if not clean_line:
                        continue
                    
                    # Print progress and other info
                    logger.info(f"📊 [nmap] {clean_line}")

        process.wait()
        return_code = process.returncode

        # Read the XML content from the file
        xml_content = ""
        if os.path.exists(xml_path):
            with open(xml_path, "r") as f:
                xml_content = f.read()
            try:
                os.remove(xml_path)
            except:
                pass
        
        if return_code != 0:
            logger.error(f"[nmap] Command failed with return code {return_code}")
            return json.dumps({
                "success": False,
                "error": f"Command failed with return code {return_code}",
                "stdout": "".join(full_output)
            })

        logger.info(f"[nmap] Command completed successfully")
        logger.info(f"[nmap] XML output length: {len(xml_content)} bytes")

        # Save raw XML to storage
        os.makedirs("/tmp/secops_results", exist_ok=True)
        with open("/tmp/secops_results/nmap_raw.xml", "w") as f:
            f.write(xml_content)

        # Parse the output
        import xml.etree.ElementTree as ET
        parsed_hosts = []
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall('host'):
                ip = host.find('address').attrib.get('addr')
                hostnames = [hn.attrib.get('name') for hn in host.findall('.//hostname')]
                ports = []
                for port in host.findall('.//port'):
                    port_id = port.attrib.get('portid')
                    protocol = port.attrib.get('protocol')
                    state = port.find('state').attrib.get('state')
                    service_node = port.find('service')
                    service_name = service_node.attrib.get('name') if service_node is not None else "unknown"
                    if state == "open":
                        ports.append({
                            "port": port_id,
                            "protocol": protocol,
                            "state": state,
                            "service": service_name
                        })
                parsed_hosts.append({
                    "ip": ip,
                    "hostnames": hostnames,
                    "open_ports": ports
                })
        except Exception as pe:
            logger.error(f"[nmap] Failed to parse XML: {pe}")
            # Fallback to a snippet of stdout if parsing fails
            return json.dumps({
                "success": True,
                "target": target,
                "warning": f"XML parsing failed: {str(pe)}",
                "raw_snippet": xml_content[:2000]
            })

        return json.dumps({
            "success": True,
            "target": target,
            "results": parsed_hosts
        })

    except Exception as e:
        logger.error(f"[nmap] Exception: {str(e)}")
        return json.dumps({
            "success": False,
            "error": str(e)
        })