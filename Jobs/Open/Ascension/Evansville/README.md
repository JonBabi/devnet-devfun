# Extreme Networks Switch Configuration Toolkit

A Python toolkit to automate the collection, parsing, and analysis of configurations from Extreme Networks switches.

## Features

### Data Collection (extreme_switch_collector.py)
- Connects to multiple Extreme Networks switches via SSH using Netmiko
- Collects full switch configuration (`show run`)
- Collects additional show commands based on switch type (Core or IDF)
- **Automatic device type selection** - Core switches use extreme_vsp, IDF switches use extreme_ers
- Tests credentials on first switch to prevent account lockout
- Automatically retries failed connections once
- Generates detailed output files with hostname and IP address
- Creates summary report of successful and failed collections

### LLDP Neighbor Parsing (parse_lldp_neighbors.py)
- Parses LLDP neighbor information from collected show command outputs
- Extracts IP addresses and hostnames from multi-line VSP LLDP format
- Generates CSV files with discovered neighbor relationships (Core switches only)
- Useful for network topology mapping and documentation

### Switch Inventory Parsing (parse_switch_inventory.py)
- Parses collected configurations to create site-organized CSV inventory files
- Extracts interface information: port status, transceivers, connected devices, VLANs, port-channels
- Combines data from show commands and running config files
- Groups switches by site identifier (extracted from hostname)
- Only includes operationally "up" ports
- Generates ready-to-use documentation for network audits

### General Features
- **Comprehensive logging** - Logs to both console and timestamped log file
- **Configurable settings** - Timeouts and fallback device type via config.json
- **Windows compatible** - UTF-8 encoding and proper path handling
- **Debug mode** - All scripts support `--debug` flag for detailed troubleshooting
- Minimal dependencies (only requires Netmiko)

## Prerequisites

- Python 3.6 or higher
- Network connectivity to the switches
- Valid SSH credentials with appropriate privileges

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

### 1. Setup Configuration (Optional)

Edit `config.json` to customize timeouts and fallback device type:
```json
{
  "device_type": "extreme",
  "connection_timeout": 20,
  "command_timeout": 30,
  "show_run_timeout": 60,
  "enable_session_log": false
}
```

**Automatic Device Type Selection:**

The script automatically selects the appropriate Netmiko device type based on the switch type in your CSV:

- **Core switches** → `extreme_vsp` (Fabric Engine/VOSS)
- **IDF switches** → `extreme_ers` (ERS switches)
- **Unknown types** → Uses `device_type` from config.json as fallback (default: `extreme`)

You typically don't need to modify the `device_type` setting unless you have switches with custom types in your CSV.

### 2. Setup Credentials

The script supports three methods for providing credentials (in order of preference):

#### Option 1: Environment Variables (Most Secure)
```bash
export SWITCH_USERNAME=admin
export SWITCH_PASSWORD=your_password_here
# Optional: export SWITCH_ENABLE_PASSWORD=enable_password
```

#### Option 2: credentials.env File (Recommended - No Escaping Needed)
Create `credentials.env` file (copy from `credentials.env.example`):
```
SWITCH_USERNAME=admin
SWITCH_PASSWORD=your_password_here
```

**Advantages:**
- Simple KEY=VALUE format
- No escaping needed for special characters like `\` or `/`
- Supports passwords with any characters

#### Option 3: credentials.json (Backward Compatible)
Edit `credentials.json` with your switch credentials:
```json
{
  "username": "admin",
  "password": "your_password_here"
}
```

**Note:** If using JSON and your password contains backslashes, you must escape them as `\\` (e.g., `"pass\\word"`)

### 3. Configure Switch List

Edit `switches.csv` with your switch IP addresses and types:
```csv
ip_address,switch_type
10.1.1.1,Core
10.1.1.2,Core
10.1.2.1,IDF
10.1.2.2,IDF
```

**Note:** Switch types must be either `Core` or `IDF`

### 4. Customize Show Commands (Optional)

Edit the show command files to customize which commands are executed:

- `show_commands_Core.txt` - Commands for Core switches
- `show_commands_IDF.txt` - Commands for IDF/Access switches

One command per line. Lines starting with `#` are treated as comments and ignored.

## Quick Start

### Complete Workflow

1. **Collect data from switches:**
```bash
python extreme_switch_collector.py
```

2. **Parse LLDP neighbor relationships (optional):**
```bash
python parse_lldp_neighbors.py
```

3. **Generate site-organized inventory CSV files:**
```bash
python parse_switch_inventory.py
```

## Detailed Usage

### 1. Data Collection (extreme_switch_collector.py)

Run the script:
```bash
python extreme_switch_collector.py

# Debug mode with detailed logging
python extreme_switch_collector.py --debug
```

### What Happens

1. Script loads credentials from `credentials.json`
2. Loads switch list from `switches.csv`
3. Tests credentials on the first switch
4. If credential test passes, proceeds to collect data from all switches
5. For each switch:
   - Connects via SSH
   - Runs `show run`
   - Extracts hostname from configuration
   - Runs additional show commands based on switch type
   - Saves output to text files
   - Retries once if connection fails

### Output Files

All output files are saved in the `switch_configs/` directory:

- `{ip_address}_{hostname}_show_run.txt` - Full switch configuration
- `{ip_address}_{hostname}_show_commands.txt` - Additional show commands output

Additional files created:
- `collection_log_{timestamp}.log` - Complete log of the collection session
- `failed_switches.txt` - List of switches that need manual review (if any fail)

### Example Output

```
================================================================================
Extreme Networks Switch Configuration Collector
================================================================================

Loaded 5 switches from CSV

Testing credentials on 10.1.1.1...
Credentials test PASSED. Proceeding with collection...

Connecting to 10.1.1.1 (Core)...
  Collecting 'show run' from 10.1.1.1...
  Detected hostname: Core-SW1
  Collecting 13 additional commands...
    Running: show version
    Running: show switch
    ...
  Saved: switch_configs/10.1.1.1_Core-SW1_show_run.txt
  Saved: switch_configs/10.1.1.1_Core-SW1_show_commands.txt

...

================================================================================
COLLECTION SUMMARY
================================================================================

Successful: 4/5
  [OK] 10.1.1.1 - Core-SW1 (Core)
  [OK] 10.1.1.2 - Core-SW2 (Core)
  [OK] 10.1.2.1 - IDF-SW1 (IDF)
  [OK] 10.1.2.2 - IDF-SW2 (IDF)

Failed: 1/5
  [FAILED] 10.1.2.3 (IDF)

Failed switches saved to: failed_switches.txt

================================================================================
Collection complete!
================================================================================
```

### 2. LLDP Neighbor Parsing (parse_lldp_neighbors.py)

After collecting data from switches, parse LLDP neighbor relationships:

```bash
python parse_lldp_neighbors.py

# Debug mode with detailed logging
python parse_lldp_neighbors.py --debug
```

#### What It Does

- Scans the `switch_configs/Core/` directory for collected show commands
- Parses LLDP neighbor information from Core switches (VSP format)
- Extracts connected device hostnames, models, and IP addresses
- Creates CSV files for each switch showing neighbor relationships

#### Output Files

LLDP neighbor data is saved to the `lldp_neighbors/` directory:
- `{hostname}_LLDP_Neighbors.csv` - One file per switch

#### CSV Format

| Switch | Local Port | Remote Device | Remote Port | Remote IP | Remote Model |
|--------|-----------|---------------|-------------|-----------|--------------|
| Core-SW1 | 1/47 | IDF-SW1 | mgmtEthernet 1 | 10.1.2.1 | VSP-7254XSQ |

#### Example Output

```
================================================================================
LLDP Neighbor Parser for Extreme Networks Switches
================================================================================

Found 2 Core switch files to process

Processing: switch_configs/Core/10.1.1.1_Core-SW1_show_commands.txt
  Hostname: Core-SW1
  Found 24 LLDP neighbors
  Saved: lldp_neighbors/Core-SW1_LLDP_Neighbors.csv

Processing: switch_configs/Core/10.1.1.2_Core-SW2_show_commands.txt
  Hostname: Core-SW2
  Found 18 LLDP neighbors
  Saved: lldp_neighbors/Core-SW2_LLDP_Neighbors.csv

================================================================================
SUMMARY
================================================================================

Total switches processed: 2
Total LLDP neighbors found: 42

All LLDP neighbor files saved to: lldp_neighbors/
```

### 3. Switch Inventory Parsing (parse_switch_inventory.py)

Generate site-organized CSV inventory files from collected configurations:

```bash
python parse_switch_inventory.py

# Debug mode with detailed logging
python parse_switch_inventory.py --debug

# Specify custom directories
python parse_switch_inventory.py --config-dir switch_configs/Core --output-dir custom_inventory
```

#### What It Does

- Parses collected switch configurations and show command outputs
- Extracts comprehensive interface information for each port
- Groups switches by site identifier (e.g., NSX, BER from hostname)
- Combines data from multiple sources:
  - Port status, speed, duplex from `show interfaces gigabitethernet`
  - Transceiver types from `show pluggable-optical-modules`
  - Connected devices from LLDP or interface descriptions
  - VLAN assignments from configuration files
  - Port-channel/MLT memberships

#### Output Files

Inventory files are organized by site in the `switch_inventory/` directory:
```
switch_inventory/
├── NSX/
│   └── NSX_interfaces.csv
├── BER/
│   └── BER_interfaces.csv
└── {SITE}/
    └── {SITE}_interfaces.csv
```

#### CSV Format

| Device IP | Device | Port | Transceiver | To Model | To Device | Native VLAN | VLAN | Access | Port-Channel | To Device IP |
|-----------|--------|------|-------------|----------|-----------|-------------|------|--------|--------------|--------------|
| 10.30.216.82 | INEVA-BER-TOR41-ASW-A | 1/47 | 10GbSR | VSP-8284XSQ | INEVA-STVE-BER-COR-A | | 10 20 30 | Tagged | MLT-147 | 10.30.216.83 |

#### Filtering

- **Only "up" ports are included** - Administratively down or disconnected ports are excluded
- Simplifies inventory by showing only active connections
- Reduces clutter in documentation

#### Site Identifier Extraction

Hostnames follow pattern: `LOCATION-SITE-BUILDING-TYPE-UNIT`
- Example: `INEVA-NSX-11IDF-SSW-00-A` → Site: **NSX**
- All switches from same site are combined into one CSV file

#### Example Output

```
================================================================================
Switch Inventory Parser for Extreme Networks Switches
================================================================================

Found 15 switch configuration files to process

Processing: switch_configs/Core/10.30.1.1_INEVA-NSX-11IDF-COR-A_show_run.txt
  Hostname: INEVA-NSX-11IDF-COR-A
  Site: NSX
  Found 48 interfaces
  Active (up) interfaces: 32

Processing: switch_configs/IDF/10.30.2.1_INEVA-NSX-11IDF-SSW-01-A_show_run.txt
  Hostname: INEVA-NSX-11IDF-SSW-01-A
  Site: NSX
  Found 48 interfaces
  Active (up) interfaces: 24

...

================================================================================
SUMMARY
================================================================================

Total switches processed: 15
Total sites discovered: 3

Site: NSX
  Switches: 8
  Total active ports: 247
  Output: switch_inventory/NSX/NSX_interfaces.csv

Site: BER
  Switches: 5
  Total active ports: 156
  Output: switch_inventory/BER/BER_interfaces.csv

Site: STVE
  Switches: 2
  Total active ports: 89
  Output: switch_inventory/STVE/STVE_interfaces.csv

All inventory files saved to: switch_inventory/
```

## Troubleshooting

### Authentication Failures
- Verify credentials in `credentials.json`
- Ensure the account has appropriate SSH access
- Check if the account is locked due to previous failed attempts

### Connection Timeouts
- Verify network connectivity to the switches
- Check if SSH is enabled on the switches
- Verify IP addresses in `switches.csv` are correct

### Missing Show Commands Files
- The script will warn if `show_commands_Core.txt` or `show_commands_IDF.txt` are missing
- It will continue and only collect `show run` for those switch types

### Parser Script Issues

**No files found to parse:**
- Ensure you've run `extreme_switch_collector.py` first to collect data
- Verify output files exist in `switch_configs/Core/` or `switch_configs/IDF/`
- Check file permissions

**Missing LLDP data:**
- LLDP parser only works with Core switches (VSP format)
- Ensure `show lldp neighbor` was included in `show_commands_Core.txt`
- Verify LLDP is enabled on the switches

**Empty CSV files:**
- Check that show command outputs contain expected data
- Run parser with `--debug` flag to see detailed parsing information
- Review log files in `logs/` directory

**Site identifier extraction fails:**
- Verify hostnames follow expected pattern: `LOCATION-SITE-BUILDING-TYPE-UNIT`
- Parser extracts second dash-separated segment as site identifier
- Hostnames without this pattern will be grouped under "UNKNOWN"

## Security Notes

- **IMPORTANT:** Add `credentials.json` and `credentials.env` to `.gitignore` to prevent committing credentials
- Environment variables are the most secure method for production use
- The `credentials.env` file is recommended over JSON as it doesn't require escaping special characters
- Store credentials securely and never share them
- Use least-privilege accounts when possible

## Files in This Package

### Main Scripts
- `extreme_switch_collector.py` - Data collection script (connects to switches via SSH)
- `parse_lldp_neighbors.py` - LLDP neighbor relationship parser
- `parse_switch_inventory.py` - Switch inventory CSV generator
- `convert_switch_types.py` - Inventory converter (tab-delimited to CSV)

### Configuration Files
- `config.json` - Configuration file (device type, timeouts)
- `credentials.json` or `credentials.env` - SSH credentials (not in repo)
- `switches.csv` - Switch inventory (IP addresses and types)
- `show_commands_Core.txt` - Show commands for Core switches
- `show_commands_IDF.txt` - Show commands for IDF switches

### Documentation
- `README.md` - This file (comprehensive usage guide)
- `CLAUDE.md` - Technical architecture and implementation details
- `CREDENTIAL_SETUP.md` - Detailed credential configuration guide

### Dependencies
- `requirements.txt` - Python dependencies (only Netmiko)

## Output Directory Structure

After running the complete workflow, your directory structure will look like:

```
.
├── switch_configs/          # Raw collected data
│   ├── Core/
│   │   ├── {ip}_{hostname}_show_run.txt
│   │   └── {ip}_{hostname}_show_commands.txt
│   └── IDF/
│       ├── {ip}_{hostname}_show_run.txt
│       └── {ip}_{hostname}_show_commands.txt
│
├── lldp_neighbors/          # LLDP neighbor relationships
│   └── {hostname}_LLDP_Neighbors.csv
│
├── switch_inventory/        # Site-organized inventory files
│   ├── NSX/
│   │   └── NSX_interfaces.csv
│   ├── BER/
│   │   └── BER_interfaces.csv
│   └── {SITE}/
│       └── {SITE}_interfaces.csv
│
├── logs/                    # Detailed log files
│   ├── collection_log_{timestamp}.log
│   ├── lldp_parser_{timestamp}.log
│   └── inventory_parser_{timestamp}.log
│
└── failed_switches.txt      # List of switches that failed collection (if any)
```

## Customization

### Adding New Show Commands

Simply edit the appropriate show commands file and add one command per line:

```
show version
show switch
show your_custom_command
```

### Changing Timeout Values

Edit `config.json` to modify timeout values:
```json
{
  "device_type": "extreme",
  "connection_timeout": 30,
  "command_timeout": 45,
  "show_run_timeout": 90
}
```

### Changing Device Type Mapping

If you need different device type mappings, edit the `get_device_type_from_switch_type()` function in the script:

```python
device_type_mapping = {
    'Core': 'extreme_vsp',     # Core switches use VSP (Fabric Engine/VOSS)
    'IDF': 'extreme_ers',       # IDF switches use ERS
    'Custom': 'extreme_exos'    # Add custom mappings here
}
```

The `device_type` in config.json is only used as a fallback for unrecognized switch types.

### Adding New Switch Types

To add a new switch type:

1. Add switches with the new type to `switches.csv`
2. Create a new file `show_commands_{NewType}.txt` with the commands for that type
3. Add the device type mapping in the script's `get_device_type_from_switch_type()` function
4. The script will automatically use it

## License

This script is provided as-is for network automation purposes.
