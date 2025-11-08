"""
LLDP Neighbor Parser for Extreme Networks VSP Switches
Parses show lldp neighbor output from collected show command files
and creates CSV files with neighbor IP addresses and hostnames.
"""

import os
import re
import csv
import logging
import argparse
from datetime import datetime


def setup_logging(debug=False):
    """Setup logging to both file and console."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create logs directory if it doesn't exist
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    # Save log file in logs directory
    log_filename = os.path.join(logs_dir, f"lldp_parser_{timestamp}.log")

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # File handler - level depends on debug flag
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    if debug:
        file_handler.setLevel(logging.DEBUG)
    else:
        file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return log_filename


def find_core_switch_files(config_dir='switch_configs'):
    """
    Find all Core switch show_commands files in the Core subdirectory.

    Returns:
        List of tuples: [(file_path, ip, hostname), ...]
    """
    core_files = []

    # Look specifically in the Core subdirectory
    core_dir = os.path.join(config_dir, 'Core')

    if not os.path.exists(core_dir):
        logging.error(f"Core switch directory '{core_dir}' not found.")
        logging.info(f"Expected directory structure: {config_dir}/Core/")
        return core_files

    # Look for files matching pattern: *_show_commands.txt
    for filename in os.listdir(core_dir):
        if filename.endswith('_show_commands.txt'):
            file_path = os.path.join(core_dir, filename)

            # Extract hostname from filename: IP_HOSTNAME_show_commands.txt
            parts = filename.replace('_show_commands.txt', '').split('_', 1)
            if len(parts) == 2:
                ip, hostname = parts
                core_files.append((file_path, ip, hostname))
                logging.debug(f"Found file: {filename} -> IP: {ip}, Hostname: {hostname}")
            else:
                logging.warning(f"Could not parse filename: {filename}")

    logging.info(f"Found {len(core_files)} Core switch show_commands files")
    return core_files


def extract_lldp_section(file_content):
    """
    Extract the 'show lldp neighbor' section from show commands output.

    Format in file:
    ================================================================================
    show lldp neighbor
    ================================================================================
    ************************************************************************************
            Command Execution Time: Mon Nov 03 14:38:30 2025 CST
    ************************************************************************************

    ==========================================================================================
                                          LLDP Neighbor
    ==========================================================================================

    Port: 2/1/1     Index    : 4
    ...
    ================================================================================
    <next command>
    ================================================================================

    Args:
        file_content: Full content of show_commands file

    Returns:
        String containing just the LLDP neighbor output, or None if not found
    """
    # Pattern to match from "show lldp neighbor" header to next command separator
    # Accounts for the asterisk headers and "LLDP Neighbor" section header
    patterns = [
        # Match: ===\nshow lldp neighbor\n===\n<content including ***>===\n
        r'={80}\s*show lldp neighbor\s*={80}\s*\n(.*?)(?:\n={80}\n|\Z)',
        r'={80}\s*sho lldp neighbor\s*={80}\s*\n(.*?)(?:\n={80}\n|\Z)',
    ]

    for pattern in patterns:
        match = re.search(pattern, file_content, re.DOTALL | re.IGNORECASE)
        if match:
            lldp_output = match.group(1).strip()
            # Verify we got meaningful output (should contain "Port:" entries)
            if lldp_output and ('Port:' in lldp_output or 'LLDP Neighbor' in lldp_output):
                logging.debug(f"Found LLDP section ({len(lldp_output)} chars)")
                return lldp_output

    logging.debug("No LLDP neighbor section found in file")
    return None


def parse_lldp_neighbors(lldp_output):
    """
    Parse LLDP neighbor output to extract IP addresses and SysNames.

    VSP LLDP output format is multi-line blocks per neighbor:
    Port: 2/1/1     Index    : 4
                    Protocol : LLDP
                    ChassisId: MAC Address        d4:78:56:9d:14:00
                    PortId   : IfName             1/3
                    SysName  : INEVA-STVE-BER-COR-A
                    SysCap   : Br / Br
                    PortDescr: Extreme Networks Virtual Services Platform 8284XSQ - 10GbSR Port 1/3
                    SysDescr : VSP-8284XSQ (8.10.3.0)
                    Address  : 10.30.216.82
               IPv6 Address  :

    Args:
        lldp_output: String containing LLDP neighbor table output

    Returns:
        List of dictionaries: [{'ip': '10.1.1.1', 'hostname': 'SWITCH-NAME'}, ...]
    """
    neighbors = []

    # Split into lines
    lines = lldp_output.split('\n')

    current_entry = {}

    for line in lines:
        # Check if this is a new Port entry (starts with "Port:")
        if line.strip().startswith('Port:'):
            # Save previous entry if complete
            if current_entry and current_entry.get('ip') and current_entry.get('hostname'):
                neighbors.append(current_entry.copy())
                logging.debug(f"Completed neighbor: {current_entry}")

            # Start new entry
            current_entry = {'ip': None, 'hostname': None}
            continue

        # Look for SysName in the current block
        sysname_match = re.search(r'SysName\s*:\s*(\S+)', line, re.IGNORECASE)
        if sysname_match:
            current_entry['hostname'] = sysname_match.group(1).strip()
            logging.debug(f"  Found SysName: {current_entry['hostname']}")
            continue

        # Look for IP Address in the current block
        # Match "Address  : 10.30.216.82" but NOT "IPv6 Address"
        if 'IPv6' not in line:
            ip_match = re.search(r'Address\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line, re.IGNORECASE)
            if ip_match:
                current_entry['ip'] = ip_match.group(1).strip()
                logging.debug(f"  Found Address: {current_entry['ip']}")
                continue

    # Don't forget the last entry
    if current_entry and current_entry.get('ip') and current_entry.get('hostname'):
        neighbors.append(current_entry)
        logging.debug(f"Completed neighbor (last): {current_entry}")

    # Filter out incomplete entries
    neighbors = [n for n in neighbors if n.get('ip') and n.get('hostname')]

    logging.info(f"Parsed {len(neighbors)} LLDP neighbors with IP addresses and hostnames")
    return neighbors


def write_neighbors_csv(hostname, neighbors, output_dir='lldp_neighbors'):
    """
    Write LLDP neighbors to CSV file.

    Args:
        hostname: Hostname of the switch being processed
        neighbors: List of neighbor dictionaries
        output_dir: Directory to save CSV files

    Returns:
        Path to created CSV file, or None if no neighbors
    """
    if not neighbors:
        logging.warning(f"No neighbors to write for {hostname}")
        return None

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Create CSV filename
    csv_filename = os.path.join(output_dir, f"{hostname}_LLDP_Neighbors.csv")

    # Write CSV
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['ip_address', 'hostname']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for neighbor in neighbors:
            writer.writerow({
                'ip_address': neighbor.get('ip', 'Unknown'),
                'hostname': neighbor.get('hostname', 'Unknown')
            })

    logging.info(f"Wrote {len(neighbors)} neighbors to: {csv_filename}")
    return csv_filename


def main():
    """Main execution function."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Parse LLDP neighbor information from Extreme VSP switch show commands',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging for detailed troubleshooting'
    )
    parser.add_argument(
        '--config-dir',
        default='switch_configs',
        help='Directory containing switch configuration files (default: switch_configs)'
    )
    parser.add_argument(
        '--output-dir',
        default='lldp_neighbors',
        help='Directory to save LLDP neighbor CSV files (default: lldp_neighbors)'
    )
    args = parser.parse_args()

    # Setup logging
    log_file = setup_logging(debug=args.debug)

    logging.info("="*80)
    logging.info("LLDP Neighbor Parser for Extreme Networks VSP Switches")
    logging.info("="*80)
    if args.debug:
        logging.info("DEBUG MODE ENABLED - Detailed logs will be written to file")
    logging.info(f"Log file: {log_file}\n")

    # Find Core switch files
    logging.info(f"Searching for show_commands files in: {args.config_dir}")
    core_files = find_core_switch_files(args.config_dir)

    if not core_files:
        logging.error("No show_commands files found. Please run the collection script first.")
        return

    # Process each file
    processed = []
    skipped = []

    for file_path, ip, hostname in core_files:
        logging.info(f"\nProcessing: {hostname} ({ip})")

        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract LLDP section
            lldp_section = extract_lldp_section(content)

            if not lldp_section:
                logging.warning(f"  No 'show lldp neighbor' output found in {hostname}")
                skipped.append({'hostname': hostname, 'reason': 'No LLDP section found'})
                continue

            # Parse neighbors
            neighbors = parse_lldp_neighbors(lldp_section)

            if not neighbors:
                logging.warning(f"  No LLDP neighbors with IP addresses found for {hostname}")
                skipped.append({'hostname': hostname, 'reason': 'No neighbors with IPs'})
                continue

            # Write CSV
            csv_file = write_neighbors_csv(hostname, neighbors, args.output_dir)

            if csv_file:
                processed.append({
                    'hostname': hostname,
                    'ip': ip,
                    'neighbor_count': len(neighbors),
                    'csv_file': csv_file
                })

        except Exception as e:
            logging.error(f"  Error processing {hostname}: {str(e)}")
            skipped.append({'hostname': hostname, 'reason': str(e)})

    # Summary report
    logging.info("\n" + "="*80)
    logging.info("LLDP PARSING SUMMARY")
    logging.info("="*80)

    if processed:
        logging.info(f"\nSuccessfully processed: {len(processed)}")
        for item in processed:
            logging.info(f"  [OK] {item['hostname']} - {item['neighbor_count']} neighbors -> {item['csv_file']}")

    if skipped:
        logging.info(f"\nSkipped: {len(skipped)}")
        for item in skipped:
            logging.info(f"  [SKIPPED] {item['hostname']} - {item['reason']}")

    logging.info("\n" + "="*80)
    logging.info("LLDP parsing complete!")
    logging.info(f"CSV files saved to: {args.output_dir}/")
    logging.info("="*80)


if __name__ == "__main__":
    main()
