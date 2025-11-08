"""
Switch Inventory Parser for Extreme Networks VSP Switches
Parses show commands and running config to create site-organized CSV inventory files.

This script extracts interface information including:
- TOR port status and type
- Physical transceiver types
- Connected devices (from LLDP and port descriptions)
- VLAN assignments (native and tagged)
- Port-Channel/MLT assignments
- Connected device IP addresses
"""

import os
import re
import csv
import logging
import argparse
from datetime import datetime
from collections import defaultdict


def setup_logging(debug=False):
    """Setup logging to both file and console."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create logs directory
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    log_filename = os.path.join(logs_dir, f"inventory_parser_{timestamp}.log")

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # File handler
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
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


def extract_site_identifier(hostname):
    """
    Extract site identifier from hostname.
    Example: INEVA-NSX-11IDF-SSW-00-A -> NSX

    Args:
        hostname: Switch hostname

    Returns:
        Site identifier string
    """
    # Split hostname by dashes and take the second segment
    parts = hostname.split('-')
    if len(parts) >= 2:
        site = parts[1]
        logging.debug(f"Extracted site '{site}' from hostname '{hostname}'")
        return site

    logging.warning(f"Could not extract site from hostname '{hostname}', using 'UNKNOWN'")
    return "UNKNOWN"


def find_switch_files(config_dir='switch_configs/Core'):
    """
    Find all switch configuration file pairs in the Core directory.

    Returns:
        List of tuples: [(show_commands_file, show_run_file, ip, hostname), ...]
    """
    switches = []

    if not os.path.exists(config_dir):
        logging.error(f"Configuration directory '{config_dir}' not found")
        return switches

    # Find all show_commands files
    show_commands_files = [f for f in os.listdir(config_dir) if f.endswith('_show_commands.txt')]

    for cmd_file in show_commands_files:
        # Extract IP and hostname from filename: IP_HOSTNAME_show_commands.txt
        base_name = cmd_file.replace('_show_commands.txt', '')
        parts = base_name.split('_', 1)

        if len(parts) == 2:
            ip, hostname = parts

            # Find corresponding show_run file
            run_file = f"{base_name}_show_run.txt"
            run_path = os.path.join(config_dir, run_file)
            cmd_path = os.path.join(config_dir, cmd_file)

            if os.path.exists(run_path):
                switches.append((cmd_path, run_path, ip, hostname))
                logging.debug(f"Found switch: {hostname} ({ip})")
            else:
                logging.warning(f"Show run file not found for {hostname}: {run_file}")

    logging.info(f"Found {len(switches)} switches in {config_dir}")
    return switches


def extract_command_section(content, command_name):
    """
    Extract a specific command section from show_commands file.

    Args:
        content: Full show_commands file content
        command_name: Command to extract (e.g., "show lldp neighbor")

    Returns:
        Command output string or None
    """
    # Pattern to match command section
    pattern = rf'={{{80}}}\s*{re.escape(command_name)}\s*={{{80}}}\s*\n(.*?)(?:\n={{{80}}}\n|\Z)'

    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        output = match.group(1).strip()
        logging.debug(f"Extracted '{command_name}' section ({len(output)} chars)")
        return output

    logging.debug(f"Command '{command_name}' not found in file")
    return None


def parse_interface_status_ers(section):
    """
    Parse interface status from ERS 'show interfaces' output.

    Args:
        section: 'show interfaces' command output

    Returns:
        Dictionary: {port: {status, speed, duplex, transceiver, mlt_id, description, port_name, vlan_mode}}
    """
    interfaces = {}

    # Parse the interface table
    # Format: Port Trunk Admin   Oper Link LinkTrap Negotiation  Speed   Duplex Control
    #         1          Enable  Down Down Enabled  Enabled
    #         3          Enable  Up   Up   Enabled  Enabled     1000Mbps Full   Disable

    for line in section.split('\n'):
        # Skip header and separator lines
        if 'Port' in line or '---' in line or not line.strip():
            continue

        # Try to match port line
        # Port can be single number (1-48) or slot/port format (1/1)
        parts = line.split()
        if len(parts) < 4:
            continue

        port = parts[0]
        # Normalize port format to include slot if missing (assume slot 1 for ERS)
        if '/' not in port and port.isdigit():
            port = f"1/{port}"

        # Extract admin and oper status
        # Parts layout: [port, (trunk), admin, oper, link, linktrap, negotiation, (speed), (duplex), (control)]
        # Trunk column might be empty, so we need to handle that
        admin_idx = 1 if parts[1] in ['Enable', 'Disable'] else 2
        oper_idx = admin_idx + 1

        if oper_idx >= len(parts):
            continue

        admin_status = parts[admin_idx]
        oper_status = parts[oper_idx]

        # Extract speed and duplex if available (when port is up)
        speed = '0'
        duplex = 'unknown'
        if len(parts) >= admin_idx + 6:
            speed_str = parts[admin_idx + 5]  # e.g., "1000Mbps"
            if 'Mbps' in speed_str or 'Gbps' in speed_str:
                speed = speed_str.replace('Mbps', '').replace('Gbps', '000')
                if len(parts) >= admin_idx + 7:
                    duplex = parts[admin_idx + 6].lower()

        interfaces[port] = {
            'status': oper_status.lower(),
            'transceiver': '1000BaseTX',  # Default, will be updated from gbic-info if available
            'admin_status': admin_status.lower(),
            'speed': speed,
            'duplex': duplex,
            'mlt_id': '0',
            'description': '',
            'port_name': '',
            'vlan_mode': ''
        }

    logging.info(f"Parsed {len(interfaces)} interface entries (ERS format)")
    return interfaces


def parse_interface_status(show_commands_content):
    """
    Parse interface status from 'show interfaces gigabitethernet' (VSP) or 'show interfaces' (ERS) output.

    Returns:
        Dictionary: {port: {status, speed, duplex, transceiver, mlt_id, description, port_name, vlan_mode}}
    """
    interfaces = {}

    # Try VSP format first
    section = extract_command_section(show_commands_content, 'show interfaces gigabitethernet')

    if not section:
        # Try ERS format
        section = extract_command_section(show_commands_content, 'show interfaces')
        if section:
            # Parse ERS format
            return parse_interface_status_ers(section)
        return interfaces

    # Parse the "Port Interface" table for status
    port_interface_match = re.search(
        r'Port Interface.*?-{20,}(.*?)(?:\n\n|\Z)',
        section,
        re.DOTALL
    )

    if port_interface_match:
        for line in port_interface_match.group(1).split('\n'):
            # Match: 1/1      192   1000BaseTX       true  false    1950  a0:09:ed:75:c0:00 up     up
            match = re.match(
                r'(\d+/\d+)\s+\d+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\w+)\s+(\w+)',
                line.strip()
            )
            if match:
                port = match.group(1)
                transceiver = match.group(2)
                admin_status = match.group(3)
                oper_status = match.group(4)

                interfaces[port] = {
                    'status': oper_status,
                    'transceiver': transceiver,
                    'admin_status': admin_status,
                    'speed': '0',
                    'duplex': 'unknown',
                    'mlt_id': '0',
                    'description': '',
                    'port_name': '',
                    'vlan_mode': ''
                }

    # Parse "Port Name" table for port names, speed, duplex, and vlan mode
    port_name_match = re.search(
        r'Port Name.*?-{20,}(.*?)(?:\n\n|Port Config)',
        section,
        re.DOTALL
    )

    if port_name_match:
        for line in port_name_match.group(1).split('\n'):
            # Match: 1/1      NAME               DESCRIPTION      up       full     1000     Access
            # Extract port number first
            port_match = re.match(r'^(\d+/\d+)', line.strip())
            if port_match:
                port = port_match.group(1)
                if port in interfaces:
                    # Find the status/duplex/speed/vlan pattern at the end
                    tail_match = re.search(r'(\S+)\s+(up|down)\s+(full|half|unknown)\s+(\d+)\s+(\w+)$', line)
                    if tail_match:
                        transceiver = tail_match.group(1)
                        status = tail_match.group(2)
                        duplex = tail_match.group(3)
                        speed = tail_match.group(4)
                        vlan_mode = tail_match.group(5)

                        # Extract NAME field: everything between port number and transceiver type
                        # Find where port number ends and where transceiver pattern starts
                        port_end = line.find(port) + len(port)
                        transceiver_start = tail_match.start(1)

                        # NAME is between port number and transceiver
                        port_name = line[port_end:transceiver_start].strip()

                        # Store the parsed data
                        interfaces[port]['port_name'] = port_name
                        interfaces[port]['speed'] = speed
                        interfaces[port]['duplex'] = duplex
                        interfaces[port]['vlan_mode'] = vlan_mode

    # Parse "Port Config" table for MLT ID
    port_config_match = re.search(
        r'Port Config.*?-{20,}(.*?)(?:\n\n|\Z)',
        section,
        re.DOTALL
    )

    if port_config_match:
        for line in port_config_match.group(1).split('\n'):
            # Match: 1/1      1000BaseTX       true  core   1     0     N/A
            match = re.match(
                r'(\d+/\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)',
                line.strip()
            )
            if match:
                port = match.group(1)
                mlt_id = match.group(2)
                if port in interfaces and mlt_id != '0':
                    interfaces[port]['mlt_id'] = mlt_id

    logging.info(f"Parsed {len(interfaces)} interface entries")
    return interfaces


def parse_transceiver_info(show_commands_content):
    """
    Parse transceiver details from 'show pluggable-optical-modules basic' output.

    Returns:
        Dictionary: {port: {type, ddm_supported, vendor, part_number}}
    """
    transceivers = {}

    section = extract_command_section(show_commands_content, 'show pluggable-optical-modules basic')
    if not section:
        return transceivers

    # Parse transceiver table
    for line in section.split('\n'):
        # Match: 1/47  GbicSx         TRUE               Avaya              AA1419048-E6
        match = re.match(
            r'(\d+/\d+)\s+(\S+)\s+(TRUE|FALSE)\s+(.+)',
            line.strip()
        )
        if match:
            port = match.group(1)
            trans_type = match.group(2)
            ddm = match.group(3)
            vendor_part = match.group(4).strip()

            # Split vendor and part number
            vendor_parts = vendor_part.split(None, 1)
            vendor = vendor_parts[0] if vendor_parts else 'Unknown'
            part_num = vendor_parts[1] if len(vendor_parts) > 1 else ''

            transceivers[port] = {
                'type': trans_type,
                'ddm_supported': ddm,
                'vendor': vendor,
                'part_number': part_num.strip()
            }

    logging.info(f"Parsed {len(transceivers)} transceiver entries")
    return transceivers


def parse_lldp_neighbors_detail(show_commands_content):
    """
    Parse LLDP neighbor information from 'show lldp neighbor detail' output (IDF format).

    Returns:
        Dictionary: {port: {hostname, model, ip_address}}
    """
    neighbors = {}

    section = extract_command_section(show_commands_content, 'show lldp neighbor detail')
    if not section:
        # Try alternate command name
        section = extract_command_section(show_commands_content, 'sho lldp neighbor detail')
        if not section:
            return neighbors

    lines = section.split('\n')
    current_port = None
    current_data = {}

    for line in lines:
        # Check for port line: Port: 1/50  Index: 28                 Time: 0 days, 00:02:46
        port_match = re.match(r'Port:\s*(\d+/\d+)', line.strip())
        if port_match:
            # Save previous entry
            if current_port and current_data:
                neighbors[current_port] = current_data.copy()

            # Start new entry
            current_port = port_match.group(1)
            current_data = {
                'hostname': '',
                'model': '',
                'ip_address': ''
            }
            continue

        if current_port:
            # Look for SysName (indented format)
            sysname_match = re.search(r'SysName:\s*(\S+)', line)
            if sysname_match:
                current_data['hostname'] = sysname_match.group(1)

            # Look for SysDescr (model info, indented format)
            sysdesc_match = re.search(r'SysDescr:\s*(.+)', line)
            if sysdesc_match:
                current_data['model'] = sysdesc_match.group(1).strip()

            # Look for ChassisId with IPv4 address: ChassisId: Network address    IPv4  10.151.255.177
            chassis_ip_match = re.search(r'ChassisId:.*IPv4\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if chassis_ip_match:
                current_data['ip_address'] = chassis_ip_match.group(1)

    # Don't forget last entry
    if current_port and current_data:
        neighbors[current_port] = current_data

    logging.info(f"Parsed {len(neighbors)} LLDP neighbor entries from 'detail' format")
    return neighbors


def parse_lldp_neighbors(show_commands_content):
    """
    Parse LLDP neighbor information from 'show lldp neighbor' output (Core format).
    Also attempts to parse 'show lldp neighbor detail' (IDF format) as fallback.

    Returns:
        Dictionary: {port: {hostname, model, ip_address}}
    """
    neighbors = {}

    section = extract_command_section(show_commands_content, 'show lldp neighbor')
    if not section:
        # Try alternate command name
        section = extract_command_section(show_commands_content, 'sho lldp neighbor')
        if not section:
            # Try 'detail' format (IDF switches)
            return parse_lldp_neighbors_detail(show_commands_content)

    lines = section.split('\n')
    current_port = None
    current_data = {}

    for line in lines:
        # Check for port line: Port: 1/3       Index    : 5
        port_match = re.match(r'Port:\s*(\d+/\d+)', line.strip())
        if port_match:
            # Save previous entry
            if current_port and current_data:
                neighbors[current_port] = current_data.copy()

            # Start new entry
            current_port = port_match.group(1)
            current_data = {
                'hostname': '',
                'model': '',
                'ip_address': ''
            }
            continue

        if current_port:
            # Look for SysName
            sysname_match = re.search(r'SysName\s*:\s*(\S+)', line)
            if sysname_match:
                current_data['hostname'] = sysname_match.group(1)

            # Look for SysDescr (model info)
            sysdesc_match = re.search(r'SysDescr\s*:\s*(.+)', line)
            if sysdesc_match:
                current_data['model'] = sysdesc_match.group(1).strip()

            # Look for IP Address (not IPv6)
            if 'IPv6' not in line:
                ip_match = re.search(r'Address\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    current_data['ip_address'] = ip_match.group(1)

    # Don't forget last entry
    if current_port and current_data:
        neighbors[current_port] = current_data

    logging.info(f"Parsed {len(neighbors)} LLDP neighbor entries")
    return neighbors


def parse_port_names(show_run_content):
    """
    Parse port names/descriptions from running config.

    Returns:
        Dictionary: {port: description}
    """
    port_names = {}

    # Find interface configurations
    # Pattern: interface GigabitEthernet 1/1\nname "Description"\n
    interface_pattern = r'interface GigabitEthernet (\d+/\d+).*?(?=^interface |^#|\Z)'

    for match in re.finditer(interface_pattern, show_run_content, re.MULTILINE | re.DOTALL):
        port = match.group(1)
        config_block = match.group(0)

        # Look for name command
        name_match = re.search(r'name\s+"([^"]+)"', config_block)
        if name_match:
            port_names[port] = name_match.group(1)

    logging.info(f"Parsed {len(port_names)} port name entries from config")
    return port_names


def parse_native_vlans(show_run_content):
    """
    Parse native VLAN assignments from running config.
    Handles both VSP format (default-vlan-id) and ERS format (vlan ports pvid).

    Returns:
        Dictionary: {port: native_vlan_id}
    """
    native_vlans = {}

    # Method 1: VSP format - interface GigabitEthernet 1/1\ndefault-vlan-id 11\n
    interface_pattern = r'interface GigabitEthernet (\d+/\d+).*?(?=^interface |^#|\Z)'

    for match in re.finditer(interface_pattern, show_run_content, re.MULTILINE | re.DOTALL):
        port = match.group(1)
        config_block = match.group(0)

        # Look for default-vlan-id
        vlan_match = re.search(r'default-vlan-id\s+(\d+)', config_block)
        if vlan_match:
            native_vlans[port] = vlan_match.group(1)

    # Method 2: ERS format - vlan ports 1-2 pvid 11
    pvid_pattern = r'vlan ports ([\d,\-/]+) pvid (\d+)'

    for match in re.finditer(pvid_pattern, show_run_content):
        port_range = match.group(1)
        vlan_id = match.group(2)

        # Expand port ranges
        ports = expand_port_range(port_range)

        for port in ports:
            native_vlans[port] = vlan_id

    logging.info(f"Parsed {len(native_vlans)} native VLAN assignments")
    return native_vlans


def expand_port_range(port_range_str):
    """
    Expand port range string to list of individual ports.
    Example: "1/5-1/11,1/13" -> ["1/5", "1/6", "1/7", "1/8", "1/9", "1/10", "1/11", "1/13"]

    Args:
        port_range_str: Port range string (e.g., "1/5-1/11,1/13-1/24")

    Returns:
        List of individual port strings
    """
    ports = []

    # Split by comma
    for segment in port_range_str.split(','):
        segment = segment.strip()

        if '-' in segment:
            # Range: 1/5-1/11
            start_str, end_str = segment.split('-', 1)
            start_match = re.match(r'(\d+)/(\d+)', start_str.strip())
            end_match = re.match(r'(\d+)/(\d+)', end_str.strip())

            if start_match and end_match:
                slot = start_match.group(1)
                start_port = int(start_match.group(2))
                end_port = int(end_match.group(2))

                for port_num in range(start_port, end_port + 1):
                    ports.append(f"{slot}/{port_num}")
        else:
            # Single port: 1/5
            if re.match(r'\d+/\d+', segment):
                ports.append(segment)

    return ports


def parse_vlan_memberships(show_run_content):
    """
    Parse VLAN memberships from running config.

    Returns:
        Dictionary: {port: [vlan_ids]}
    """
    vlan_memberships = defaultdict(list)

    # Find VLAN member commands
    # Pattern: vlan members 11 1/5-1/11,1/13-1/24,1/26-1/36,1/46-1/47
    for match in re.finditer(r'vlan members (\d+) (.+)', show_run_content):
        vlan_id = match.group(1)
        port_range = match.group(2).strip()

        # Expand port ranges
        ports = expand_port_range(port_range)

        for port in ports:
            vlan_memberships[port].append(vlan_id)

    logging.info(f"Parsed VLAN memberships for {len(vlan_memberships)} ports")
    return vlan_memberships


def parse_switch_data(show_commands_file, show_run_file, ip, hostname):
    """
    Parse all data from a switch's configuration files.

    Args:
        show_commands_file: Path to show commands file
        show_run_file: Path to show run file
        ip: Switch IP address
        hostname: Switch hostname

    Returns:
        List of interface dictionaries
    """
    logging.info(f"Parsing switch: {hostname} ({ip})")

    # Read files
    try:
        with open(show_commands_file, 'r', encoding='utf-8') as f:
            show_commands_content = f.read()
        with open(show_run_file, 'r', encoding='utf-8') as f:
            show_run_content = f.read()
    except Exception as e:
        logging.error(f"Error reading files for {hostname}: {e}")
        return []

    # Parse all data
    interfaces = parse_interface_status(show_commands_content)
    transceivers = parse_transceiver_info(show_commands_content)
    lldp_neighbors = parse_lldp_neighbors(show_commands_content)
    port_names = parse_port_names(show_run_content)
    native_vlans = parse_native_vlans(show_run_content)
    vlan_memberships = parse_vlan_memberships(show_run_content)

    # Combine data
    result = []

    for port, interface_data in interfaces.items():
        # Only include ports that are operationally up
        if interface_data['status'].lower() != 'up':
            continue

        # Build row data
        row = {
            'Device IP': ip,
            'Device': hostname,
            'Port': port,
            'Transceiver': interface_data.get('transceiver', ''),
            'To Model': '',
            'To Device': '',
            'Native VLAN': '',
            'VLAN': '',
            'Access': interface_data.get('vlan_mode', ''),
            'Port-Channel': '',
            'To Device IP': ''
        }

        # Add transceiver details if available
        if port in transceivers:
            trans = transceivers[port]
            row['Transceiver'] = trans['type']

        # Add LLDP neighbor info
        if port in lldp_neighbors:
            neighbor = lldp_neighbors[port]
            row['To Device'] = neighbor.get('hostname', '')
            row['To Model'] = neighbor.get('model', '')
            row['To Device IP'] = neighbor.get('ip_address', '')

        # Add port name as fallback for To Device (multi-tier fallback)
        # Priority: 1) LLDP hostname, 2) show_run port name, 3) show_commands port name
        if not row['To Device'] and port in port_names:
            row['To Device'] = port_names[port]

        if not row['To Device'] and interface_data.get('port_name'):
            row['To Device'] = interface_data['port_name']

        # Add native VLAN
        if port in native_vlans:
            row['Native VLAN'] = native_vlans[port]

        # Add tagged VLANs (comma-separated)
        if port in vlan_memberships:
            vlans = vlan_memberships[port]
            # Remove native VLAN from tagged list if present
            if row['Native VLAN']:
                vlans = [v for v in vlans if v != row['Native VLAN']]
            row['VLAN'] = ','.join(vlans)

        # Add MLT/Port-Channel
        if interface_data.get('mlt_id', '0') != '0':
            row['Port-Channel'] = f"MLT-{interface_data['mlt_id']}"

        result.append(row)

    logging.info(f"Extracted {len(result)} active interfaces from {hostname}")
    return result


def write_site_csv(site, interfaces_data, output_dir='switch_inventory'):
    """
    Write interface data to CSV file for a site.

    Args:
        site: Site identifier
        interfaces_data: List of interface dictionaries
        output_dir: Base output directory
    """
    if not interfaces_data:
        logging.warning(f"No data to write for site {site}")
        return

    # Create site directory
    site_dir = os.path.join(output_dir, site)
    os.makedirs(site_dir, exist_ok=True)

    # CSV filename
    csv_file = os.path.join(site_dir, f"{site}_interfaces.csv")

    # Write CSV
    fieldnames = [
        'Device IP', 'Device', 'Port', 'Transceiver', 'To Model', 'To Device',
        'Native VLAN', 'VLAN', 'Access', 'Port-Channel', 'To Device IP'
    ]

    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(interfaces_data)

    logging.info(f"Wrote {len(interfaces_data)} interface entries to: {csv_file}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Parse Extreme Networks switch configurations and create inventory CSVs',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--config-dir',
        default='switch_configs/Core',
        help='Directory containing switch configuration files (default: switch_configs/Core)'
    )
    parser.add_argument(
        '--output-dir',
        default='switch_inventory',
        help='Directory to save inventory CSV files (default: switch_inventory)'
    )
    args = parser.parse_args()

    # Setup logging
    log_file = setup_logging(debug=args.debug)

    logging.info("="*80)
    logging.info("Switch Inventory Parser for Extreme Networks VSP Switches")
    logging.info("="*80)
    if args.debug:
        logging.info("DEBUG MODE ENABLED")
    logging.info(f"Log file: {log_file}\n")

    # Find switch files
    logging.info(f"Scanning for switches in: {args.config_dir}")
    switches = find_switch_files(args.config_dir)

    if not switches:
        logging.error("No switch configuration files found")
        return

    # Group switches by site
    site_data = defaultdict(list)

    for show_commands_file, show_run_file, ip, hostname in switches:
        site = extract_site_identifier(hostname)

        # Parse switch data
        interfaces = parse_switch_data(show_commands_file, show_run_file, ip, hostname)

        if interfaces:
            site_data[site].extend(interfaces)

    # Write CSVs for each site
    logging.info(f"\n{'='*80}")
    logging.info("Writing CSV files...")
    logging.info(f"{'='*80}\n")

    for site, interfaces in site_data.items():
        write_site_csv(site, interfaces, args.output_dir)

    # Summary
    logging.info(f"\n{'='*80}")
    logging.info("PARSING SUMMARY")
    logging.info(f"{'='*80}")
    logging.info(f"Total switches processed: {len(switches)}")
    logging.info(f"Sites discovered: {len(site_data)}")
    for site, interfaces in site_data.items():
        logging.info(f"  {site}: {len(interfaces)} active interfaces")

    logging.info(f"\nOutput directory: {args.output_dir}/")
    logging.info(f"{'='*80}")
    logging.info("Parsing complete!")
    logging.info(f"{'='*80}")


if __name__ == "__main__":
    main()
