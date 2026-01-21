import subprocess
import json
from typing import Optional, Dict, Any, List


def run_hashcat(
    hash_file: str,
    wordlist: str,
    mode: Optional[int] = 0,  # Default to MD5
    options: Optional[List[str]] = None,
) -> str:
    """Run Hashcat to crack hashes.
    
    Args:
        hash_file: Path to file containing hashes
        wordlist: Path to wordlist file
        mode: Hash type (e.g., 0 for MD5, 1000 for NTLM)
        options: Additional hashcat options (e.g., ["--force", "-O"])
    
    Returns:
        str: JSON string containing cracking results
    """
    try:
        # Build the command
        cmd = ["/tools/hashcat/hashcat.bin", "-m", str(mode), "--potfile-disable", "--outfile-format=2"]
        if options: cmd.extend(options)
        cmd.extend([hash_file, wordlist])
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the output
        return json.dumps({
            "success": True,
            "hash_file": hash_file,
            "mode": mode,
            "results": {
                "output": result.stdout,
                "cracked_hashes": []  # Hashcat output format 2 would be parsed here
            }
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