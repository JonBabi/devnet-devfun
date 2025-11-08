"""
Extreme Networks Switch Configuration Collector
This script connects to Extreme Networks switches via SSH using Netmiko,
collects show run and additional show commands based on switch type,
and saves the output to text files.
"""

import csv
import json
import os
import re
import logging
import argparse
from datetime import datetime
from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoTimeoutException, NetMikoAuthenticationException, ReadTimeout
from tqdm import tqdm


class TqdmLoggingHandler(logging.StreamHandler):
    """Custom logging handler that uses tqdm.write() to avoid interfering with progress bars."""
    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)


def load_config(config_file='config.json'):
    """Load configuration from JSON file."""
    defaults = {
        'device_type': 'extreme',
        'connection_timeout': 20,
        'command_timeout': 30,
        'show_run_timeout': 60,
        'enable_session_log': False
    }

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        # Merge with defaults
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
        return config
    except FileNotFoundError:
        logging.warning(f"Warning: {config_file} not found. Using default settings.")
        return defaults
    except json.JSONDecodeError:
        logging.warning(f"Warning: {config_file} is not valid JSON. Using default settings.")
        return defaults


def load_credentials(creds_file='credentials.json'):
    """
    Load credentials from multiple sources (in order of preference):
    1. Environment variables (SWITCH_USERNAME, SWITCH_PASSWORD, SWITCH_ENABLE_PASSWORD)
    2. .env file (simple KEY=VALUE format, no escaping needed)
    3. credentials.json (backward compatible, requires \\ for backslashes)

    Returns:
        tuple: (username, password, enable_password)
    """
    # Method 1: Check environment variables first
    username = os.environ.get('SWITCH_USERNAME')
    password = os.environ.get('SWITCH_PASSWORD')
    enable_password = os.environ.get('SWITCH_ENABLE_PASSWORD')

    if username and password:
        # Enable password defaults to login password if not specified
        enable_password = enable_password or password
        logging.info("Credentials loaded from environment variables")
        return username, password, enable_password

    # Method 2: Try .env file (simple format, no escaping needed)
    env_file = 'credentials.env'
    if os.path.exists(env_file):
        try:
            creds = {}
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    # Split on first = only
                    if '=' in line:
                        key, value = line.split('=', 1)
                        # Remove quotes if present
                        value = value.strip().strip('"').strip("'")
                        creds[key.strip()] = value

            username = creds.get('SWITCH_USERNAME') or creds.get('username')
            password = creds.get('SWITCH_PASSWORD') or creds.get('password')
            enable_password = creds.get('SWITCH_ENABLE_PASSWORD') or creds.get('enable_password')

            if username and password:
                enable_password = enable_password or password
                logging.info(f"Credentials loaded from {env_file}")
                return username, password, enable_password
        except Exception as e:
            logging.warning(f"Warning: Could not read {env_file}: {str(e)}")

    # Method 3: Try JSON file (backward compatible)
    try:
        with open(creds_file, 'r', encoding='utf-8') as f:
            creds = json.load(f)
        username = creds.get('username')
        password = creds.get('password')
        enable_password = creds.get('enable_password', password)

        if username and password:
            logging.info(f"Credentials loaded from {creds_file}")
            return username, password, enable_password
    except FileNotFoundError:
        pass  # Will show error below
    except json.JSONDecodeError as e:
        logging.error(f"Error: {creds_file} is not valid JSON: {str(e)}")
        logging.error("Tip: In JSON, backslashes must be escaped as \\\\ (e.g., pass\\\\word)")
        return None, None, None

    # No credentials found
    logging.error("Error: No credentials found. Please use one of these methods:")
    logging.error("  1. Environment variables: SWITCH_USERNAME, SWITCH_PASSWORD")
    logging.error("  2. Create credentials.env file with format:")
    logging.error("     SWITCH_USERNAME=admin")
    logging.error("     SWITCH_PASSWORD=your_password_here")
    logging.error("  3. Create credentials.json (requires escaping \\ as \\\\)")
    return None, None, None


def load_show_commands(switch_type):
    """Load show commands based on switch type."""
    filename = f"show_commands_{switch_type}.txt"
    try:
        with open(filename, 'r') as f:
            commands = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return commands
    except FileNotFoundError:
        logging.warning(f"Warning: {filename} not found. Skipping additional show commands for {switch_type} switches.")
        return []


def load_switches_from_csv(csv_file='switches.csv'):
    """Load switch IP addresses and types from CSV file."""
    switches = []
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('ip_address', '').strip()
                switch_type = row.get('switch_type', '').strip()
                if ip and switch_type:
                    switches.append({'ip': ip, 'type': switch_type})
        return switches
    except FileNotFoundError:
        logging.error(f"Error: {csv_file} not found.")
        return []


def send_command_with_retry(connection, command, read_timeout=30, max_retries=2):
    """
    Send command with fallback strategies for pattern detection failures.

    Tries multiple approaches:
    1. Standard send_command with explicit expect_string
    2. Retry with increased timeout and different strip settings
    3. Use timing-based method as last resort (for large outputs with paging issues)

    Args:
        connection: Netmiko connection object
        command: Command string to send
        read_timeout: Initial timeout in seconds
        max_retries: Maximum number of retry attempts

    Returns:
        Command output string

    Raises:
        Exception if all methods fail
    """
    for attempt in range(max_retries):
        try:
            # Try with explicit prompt pattern
            if attempt == 0:
                logging.debug(f"    Attempt {attempt+1}: Standard send_command with timeout={read_timeout}s")
                output = connection.send_command(
                    command,
                    expect_string=r"[>#]\s*$",
                    read_timeout=read_timeout
                )
                logging.debug(f"    Success with standard send_command")
                return output

            elif attempt == 1:
                # Retry with increased timeout and different settings
                increased_timeout = int(read_timeout * 1.5)
                logging.debug(f"    Attempt {attempt+1}: Retry with timeout={increased_timeout}s, strip_prompt=False")
                output = connection.send_command(
                    command,
                    expect_string=r"[>#]\s*$",
                    read_timeout=increased_timeout,
                    strip_prompt=False,
                    strip_command=False
                )
                logging.debug(f"    Success with increased timeout")
                return output

        except ReadTimeout as e:
            if attempt < max_retries - 1:
                logging.warning(
                    f"    Pattern detection timeout on '{command}' (attempt {attempt+1}/{max_retries}). "
                    f"Error: {str(e)[:100]}"
                )
                continue
            else:
                # Last resort: use timing-based method (doesn't wait for prompt pattern)
                logging.warning(
                    f"    All pattern-based attempts failed. Trying timing-based method for '{command}'"
                )
                try:
                    output = connection.send_command_timing(command, delay_factor=2)
                    logging.info(f"    Success with timing-based send_command")
                    return output
                except Exception as timing_error:
                    logging.error(f"    Timing-based command also failed: {str(timing_error)}")
                    raise Exception(
                        f"Command '{command}' failed with all methods. "
                        f"Last error: {str(timing_error)}"
                    )

        except Exception as e:
            logging.error(f"    Unexpected error on '{command}': {str(e)}")
            if attempt == max_retries - 1:
                raise
            continue

    raise Exception(f"Command '{command}' failed after {max_retries} attempts")


def get_device_type_from_switch_type(switch_type, fallback_device_type='extreme'):
    """
    Map switch type to Netmiko device type.
    Core switches use extreme_vsp, IDF switches use extreme_ers.
    """
    device_type_mapping = {
        'Core': 'extreme_vsp',
        'IDF': 'extreme_ers'
    }

    device_type = device_type_mapping.get(switch_type, fallback_device_type)

    if switch_type not in device_type_mapping:
        logging.warning(f"Unknown switch type '{switch_type}'. Using fallback device type: {fallback_device_type}")

    return device_type


def get_hostname_from_device(connection, device_type):
    """
    Query the device directly for its hostname using appropriate commands.
    This is more reliable than parsing show run output.
    """
    hostname_commands = []

    # Different commands based on device type
    if 'vsp' in device_type.lower():
        # VSP switches (Fabric/Core)
        hostname_commands = [
            'show sys-info | include sysName',
            'show system | include System Name',
            'show sys-info',
        ]
    elif 'ers' in device_type.lower():
        # ERS switches (IDF)
        hostname_commands = [
            'show sys-info | include sysName',
            'show system info | include sysName',
            'show sys info',
        ]
    elif 'exos' in device_type.lower():
        # EXOS switches
        hostname_commands = [
            'show switch | include SysName',
            'show switch',
        ]
    else:
        # Generic Extreme commands
        hostname_commands = [
            'show sys-info | include sysName',
            'show system | include System Name',
            'show switch | include SysName',
        ]

    # Try each command
    for cmd in hostname_commands:
        try:
            logging.debug(f"    Trying hostname command: {cmd}")
            output = send_command_with_retry(connection, cmd, read_timeout=10)
            logging.debug(f"    Command output: {output[:200]}")  # Log first 200 chars

            # Parse the output
            hostname = parse_hostname_from_output(output)
            if hostname and hostname != "unknown":
                logging.info(f"    Hostname found via '{cmd}': {hostname}")
                return hostname
        except Exception as e:
            logging.debug(f"    Command '{cmd}' failed: {str(e)}")
            continue

    return None


def parse_hostname_from_output(output):
    """Parse hostname from command output using multiple patterns."""
    # List of regex patterns to try
    patterns = [
        # VSP/ERS patterns
        r'sysName\s*:\s*([^\s\r\n]+)',
        r'sysName[:\s]+([^\s\r\n]+)',
        r'System Name[:\s]+([^\s\r\n]+)',
        # EXOS patterns
        r'SysName[:\s]+([^\s\r\n]+)',
        r'System\s+Name:\s*([^\s\r\n]+)',
        # Config file patterns
        r'configure\s+snmp\s+sysName\s+"?([^"\n]+)"?',
        r'set\s+system\s+name\s+"?([^"\n]+)"?',
        r'hostname\s+"?([^"\n]+)"?',
        r'sys-name\s+"?([^"\n]+)"?',
        r'snmp-server\s+name\s+([^\s\r\n]+)',
        # Prompt pattern (last resort)
        r'^([A-Za-z0-9][A-Za-z0-9\-_\.]+)[\#>]',
    ]

    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
        if match:
            hostname = match.group(1).strip()
            # Clean up the hostname
            hostname = hostname.strip('"\'')
            # Validate it's not empty and doesn't contain invalid characters
            if hostname and len(hostname) > 0 and hostname.lower() not in ['unknown', 'switch', 'none', 'null', 'default']:
                logging.debug(f"    Matched pattern: {pattern} -> {hostname}")
                return hostname

    return "unknown"


def extract_hostname(show_run_output):
    """Extract hostname from show run output (fallback method)."""
    return parse_hostname_from_output(show_run_output)


def test_credentials(ip, username, password, enable_password, switch_type, config):
    """Test credentials on first switch before proceeding."""
    device_type = get_device_type_from_switch_type(switch_type, config['device_type'])

    logging.info(f"\nTesting credentials on {ip}...")
    logging.info(f"  Switch Type: {switch_type} -> Device Type: {device_type}")

    device = {
        'device_type': device_type,
        'ip': ip,
        'username': username,
        'password': password,
        'secret': enable_password,  # Enable password for privilege escalation
        'timeout': config['connection_timeout']
    }

    if config['enable_session_log']:
        device['session_log'] = 'netmiko_session.log'

    try:
        connection = ConnectHandler(**device)

        # For VSP switches, explicitly enter enable mode
        if 'vsp' in device_type.lower():
            logging.info("  Entering enable mode for VSP switch...")
            connection.enable()
            logging.debug(f"  Current prompt: {connection.find_prompt()}")

        connection.disconnect()
        logging.info("Credentials test PASSED. Proceeding with collection...")
        return True
    except NetMikoAuthenticationException:
        logging.error("ERROR: Authentication failed. Please check credentials.json")
        return False
    except NetMikoTimeoutException:
        logging.error(f"ERROR: Connection timeout to {ip}. Switch may be unreachable.")
        return False
    except Exception as e:
        logging.error(f"ERROR: {str(e)}")
        return False


def get_show_run_command(device_type):
    """
    Get the appropriate show running-config command for the device type.
    VSP/VOSS uses 'show running-config', ERS uses 'show running-config'.
    """
    if 'vsp' in device_type.lower():
        return 'show running-config'
    elif 'ers' in device_type.lower():
        return 'show running-config'
    elif 'exos' in device_type.lower():
        return 'show configuration'
    else:
        # Fallback
        return 'show running-config'


def connect_and_collect(switch_ip, switch_type, username, password, enable_password, config, retry=True):
    """Connect to switch and collect show commands."""
    device_type = get_device_type_from_switch_type(switch_type, config['device_type'])

    logging.info(f"\nConnecting to {switch_ip} ({switch_type} -> {device_type})...")

    device = {
        'device_type': device_type,
        'ip': switch_ip,
        'username': username,
        'password': password,
        'secret': enable_password,  # Enable password for privilege escalation
        'timeout': config['connection_timeout']
    }

    attempt = 0
    max_attempts = 2 if retry else 1

    while attempt < max_attempts:
        try:
            connection = ConnectHandler(**device)

            # For VSP switches, explicitly enter enable mode
            if 'vsp' in device_type.lower():
                logging.info(f"  Entering enable mode for VSP switch...")
                connection.enable()
                current_prompt = connection.find_prompt()
                logging.info(f"  Enable mode entered. Prompt: {current_prompt}")

                # Disable terminal paging to prevent "Press any key" prompts on large outputs
                logging.debug(f"  Disabling terminal paging...")
                try:
                    connection.send_command("terminal length 0", read_timeout=5)
                    logging.debug(f"  Terminal paging disabled")
                except Exception as e:
                    logging.debug(f"  Could not disable paging (may not be supported): {str(e)}")

            # For ERS switches, also disable paging if needed
            elif 'ers' in device_type.lower():
                logging.debug(f"  Disabling terminal paging for ERS switch...")
                try:
                    connection.send_command("terminal length 0", read_timeout=5)
                    logging.debug(f"  Terminal paging disabled")
                except Exception as e:
                    logging.debug(f"  Could not disable paging (may not be supported): {str(e)}")

            # Try to get hostname directly from device first (more reliable)
            logging.info(f"  Querying hostname from {switch_ip}...")
            hostname = get_hostname_from_device(connection, device_type)

            # Collect show run using device-specific command
            show_run_cmd = get_show_run_command(device_type)
            logging.info(f"  Collecting '{show_run_cmd}' from {switch_ip}...")
            show_run_output = send_command_with_retry(connection, show_run_cmd, read_timeout=config['show_run_timeout'])

            # If hostname wasn't found via direct query, try parsing show run
            if not hostname or hostname == "unknown":
                logging.info(f"  Attempting to extract hostname from show run output...")
                hostname = extract_hostname(show_run_output)

            logging.info(f"  Detected hostname: {hostname}")

            # Collect additional show commands based on switch type
            show_commands = load_show_commands(switch_type)
            show_commands_output = []

            if show_commands:
                logging.info(f"  Collecting {len(show_commands)} additional commands...")
                for cmd in show_commands:
                    logging.info(f"    Running: {cmd}")
                    try:
                        output = send_command_with_retry(connection, cmd, read_timeout=config['command_timeout'])
                        show_commands_output.append(f"\n{'='*80}\n{cmd}\n{'='*80}\n{output}")
                    except Exception as e:
                        logging.error(f"    Failed to collect '{cmd}': {str(e)}")
                        # Continue with other commands even if one fails
                        show_commands_output.append(f"\n{'='*80}\n{cmd}\n{'='*80}\nERROR: {str(e)}\n")

            connection.disconnect()

            # Save outputs to files
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Organize by switch type in subdirectories
            output_dir = os.path.join("switch_configs", switch_type)
            os.makedirs(output_dir, exist_ok=True)

            # Save show run
            show_run_filename = os.path.join(output_dir, f"{switch_ip}_{hostname}_show_run.txt")
            with open(show_run_filename, 'w', encoding='utf-8') as f:
                f.write(f"Configuration collected from {switch_ip} ({hostname})\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Switch Type: {switch_type}\n")
                f.write("="*80 + "\n\n")
                f.write(show_run_output)
            logging.info(f"  Saved: {show_run_filename}")

            # Save show commands
            if show_commands_output:
                show_commands_filename = os.path.join(output_dir, f"{switch_ip}_{hostname}_show_commands.txt")
                with open(show_commands_filename, 'w', encoding='utf-8') as f:
                    f.write(f"Show commands collected from {switch_ip} ({hostname})\n")
                    f.write(f"Timestamp: {timestamp}\n")
                    f.write(f"Switch Type: {switch_type}\n")
                    f.write("="*80 + "\n")
                    f.write("\n".join(show_commands_output))
                logging.info(f"  Saved: {show_commands_filename}")

            return True, hostname

        except NetMikoAuthenticationException:
            attempt += 1
            if attempt < max_attempts:
                logging.warning(f"  Authentication failed. Retrying ({attempt}/{max_attempts})...")
            else:
                logging.error(f"  ERROR: Authentication failed after {max_attempts} attempts")
                return False, None

        except NetMikoTimeoutException:
            attempt += 1
            if attempt < max_attempts:
                logging.warning(f"  Connection timeout. Retrying ({attempt}/{max_attempts})...")
            else:
                logging.error(f"  ERROR: Connection timeout after {max_attempts} attempts")
                return False, None

        except Exception as e:
            logging.error(f"  ERROR: {str(e)}")
            return False, None

    return False, None


def setup_logging(debug=False):
    """Setup logging to both file and console."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create logs directory if it doesn't exist
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    # Save log file in logs directory
    log_filename = os.path.join(logs_dir, f"collection_log_{timestamp}.log")

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Always set to DEBUG at root level

    # File handler - level depends on debug flag
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    if debug:
        file_handler.setLevel(logging.DEBUG)  # Detailed logs for troubleshooting
    else:
        file_handler.setLevel(logging.INFO)   # Clean logs for normal operation
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)

    # Console handler - only show INFO and above
    # Use TqdmLoggingHandler to avoid interfering with progress bars
    console_handler = TqdmLoggingHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return log_filename


def main():
    """Main execution function."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Extreme Networks Switch Configuration Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging for detailed troubleshooting'
    )
    args = parser.parse_args()

    # Setup logging with debug flag
    log_file = setup_logging(debug=args.debug)

    logging.info("="*80)
    logging.info("Extreme Networks Switch Configuration Collector")
    logging.info("="*80)
    if args.debug:
        logging.info("DEBUG MODE ENABLED - Detailed logs will be written to file")
    logging.info(f"Log file: {log_file}\n")

    # Load configuration
    config = load_config()
    logging.info(f"Fallback Device Type: {config['device_type']}")
    logging.info(f"Connection Timeout: {config['connection_timeout']}s")
    logging.info(f"Command Timeout: {config['command_timeout']}s")
    logging.info("Device Type Mapping: Core -> extreme_vsp, IDF -> extreme_ers\n")

    # Load credentials
    username, password, enable_password = load_credentials()
    if not username or not password:
        return

    # Load switches from CSV
    switches = load_switches_from_csv()
    if not switches:
        logging.error("No switches found in CSV file.")
        return

    logging.info(f"Loaded {len(switches)} switches from CSV")

    # Test credentials on first switch
    if switches:
        if not test_credentials(switches[0]['ip'], username, password, enable_password, switches[0]['type'], config):
            logging.error("\nCredential test failed. Exiting to prevent account lockout.")
            return

    # Process each switch
    successful = []
    failed = []

    # Create progress bar for switch processing
    with tqdm(total=len(switches), desc="Processing switches", unit="switch") as pbar:
        for switch in switches:
            # Update progress bar description with current switch
            pbar.set_postfix_str(f"Current: {switch['ip']} ({switch['type']})")

            success, hostname = connect_and_collect(
                switch['ip'],
                switch['type'],
                username,
                password,
                enable_password,
                config
            )

            if success:
                successful.append({'ip': switch['ip'], 'hostname': hostname, 'type': switch['type']})
            else:
                failed.append({'ip': switch['ip'], 'type': switch['type']})

            # Update progress bar
            pbar.update(1)

    # Generate summary report
    logging.info("\n" + "="*80)
    logging.info("COLLECTION SUMMARY")
    logging.info("="*80)
    logging.info(f"\nSuccessful: {len(successful)}/{len(switches)}")
    for s in successful:
        logging.info(f"  [OK] {s['ip']} - {s['hostname']} ({s['type']})")

    if failed:
        logging.info(f"\nFailed: {len(failed)}/{len(switches)}")
        for f in failed:
            logging.warning(f"  [FAILED] {f['ip']} ({f['type']})")

        # Save failed switches to file
        with open('failed_switches.txt', 'w', encoding='utf-8') as f:
            f.write("Failed Switches - Needs Manual Review\n")
            f.write("="*50 + "\n")
            for fail in failed:
                f.write(f"{fail['ip']},{fail['type']}\n")
        logging.info("\nFailed switches saved to: failed_switches.txt")

    logging.info("\n" + "="*80)
    logging.info("Collection complete!")
    logging.info("="*80)


if __name__ == "__main__":
    main()
