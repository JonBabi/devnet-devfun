# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a network automation toolkit for collecting and parsing configuration data from Extreme Networks switches. The project handles both Core switches (VSP/VOSS architecture) and IDF/Access switches (ERS architecture) via SSH using Netmiko.

## Architecture

### Core Scripts

**extreme_switch_collector.py** - Main data collection script
- Connects to switches via SSH and collects configurations and show command outputs
- Implements automatic device type selection: Core switches → `extreme_vsp`, IDF switches → `extreme_ers`
- Key functions:
  - `connect_and_collect()` (extreme_switch_collector.py:343) - Main collection workflow, handles connection, command execution, and file saving
  - `get_device_type_from_switch_type()` (extreme_switch_collector.py:172) - Maps switch types to Netmiko device types
  - `send_command_with_retry()` (extreme_switch_collector.py:92) - Handles command execution with fallback strategies for pattern detection failures
  - `get_hostname_from_device()` (extreme_switch_collector.py:190) - Queries device for hostname using device-specific commands
  - `test_credentials()` (extreme_switch_collector.py:285) - Tests credentials on first switch before bulk collection

**parse_lldp_neighbors.py** - LLDP neighbor parser
- Parses LLDP neighbor information from collected show command outputs (Core switches only)
- Extracts IP addresses and hostnames from multi-line VSP LLDP format
- Generates CSV files with discovered neighbor relationships
- Key functions:
  - `parse_lldp_neighbors()` (parse_lldp_neighbors.py:135) - Parses VSP multi-line LLDP format into structured data
  - `extract_lldp_section()` (parse_lldp_neighbors.py:86) - Extracts LLDP section from show commands file
  - `find_core_switch_files()` (parse_lldp_neighbors.py:51) - Locates Core switch files in organized directory structure

**parse_switch_inventory.py** - Switch inventory parser
- Parses collected switch configurations to create site-organized CSV inventory files
- Extracts interface information: port status, transceivers, connected devices, VLANs, port-channels
- Combines data from show commands and running config files
- Groups switches by site identifier (extracted from hostname)
- Only includes operationally "up" ports
- Key functions:
  - `parse_interface_status()` (parse_switch_inventory.py:163) - Parses port status, speed, duplex, MLT assignments
  - `parse_lldp_neighbors()` (parse_switch_inventory.py:254) - Extracts connected device info and IP addresses
  - `parse_native_vlans()` (parse_switch_inventory.py:437) - Extracts native VLAN from default-vlan-id commands
  - `parse_vlan_memberships()` (parse_switch_inventory.py:457) - Parses tagged VLAN assignments
  - `extract_site_identifier()` (parse_switch_inventory.py:60) - Extracts site code from hostname (e.g., INEVA-NSX-11IDF → NSX)

**convert_switch_types.py** - Inventory converter
- Converts tab-delimited switch inventory to CSV format
- Automatically classifies switches as Core or IDF based on "VSP" in machine type

### Configuration Files

- **config.json** - Timeouts and fallback device type (rarely needs changes due to automatic device type selection)
- **credentials.env** or **credentials.json** - SSH credentials (not in repo)
  - Supports three methods: environment variables, .env file (no escaping), or JSON (backward compatible)
  - .env format recommended for passwords with special characters like `\` or `/`
  - Credential loading logic at extreme_switch_collector.py:45
- **switches.csv** - Switch inventory with columns: `ip_address`, `switch_type` (Core or IDF)
- **show_commands_Core.txt** - Commands to execute on Core/VSP switches
- **show_commands_IDF.txt** - Commands to execute on IDF/ERS switches

### Output Structure

```
switch_configs/
├── Core/
│   ├── {ip}_{hostname}_show_run.txt
│   └── {ip}_{hostname}_show_commands.txt
└── IDF/
    ├── {ip}_{hostname}_show_run.txt
    └── {ip}_{hostname}_show_commands.txt

lldp_neighbors/
└── {hostname}_LLDP_Neighbors.csv

switch_inventory/
├── NSX/
│   └── NSX_interfaces.csv
├── BER/
│   └── BER_interfaces.csv
└── {site}/
    └── {site}_interfaces.csv

logs/
├── collection_log_{timestamp}.log
├── lldp_parser_{timestamp}.log
└── inventory_parser_{timestamp}.log
```

## Common Commands

### Data Collection
```bash
# Normal collection run
python extreme_switch_collector.py

# Debug mode with detailed logging
python extreme_switch_collector.py --debug
```

### LLDP Parsing
```bash
# Parse LLDP neighbors from collected data
python parse_lldp_neighbors.py

# Debug mode
python parse_lldp_neighbors.py --debug
```

### Switch Inventory Parsing
```bash
# Parse collected configs and create site-organized CSV files
python parse_switch_inventory.py

# Debug mode with detailed logging
python parse_switch_inventory.py --debug

# Specify custom directories
python parse_switch_inventory.py --config-dir switch_configs/Core --output-dir switch_inventory
```

### Inventory Conversion
```bash
# Convert switch_types.txt to switches.csv
python convert_switch_types.py
```

## Device Type Handling

The codebase automatically maps switch types to appropriate Netmiko device types:
- **Core switches** → `extreme_vsp` (Fabric Engine/VOSS)
- **IDF switches** → `extreme_ers` (ERS switches)

This mapping is implemented in `get_device_type_from_switch_type()`. The `device_type` setting in config.json only serves as a fallback for unknown switch types.

### VSP-Specific Handling
- VSP switches require explicit `enable` mode entry (extreme_switch_collector.py:308, 366)
- Terminal paging is disabled with `terminal length 0` to prevent "Press any key" prompts (extreme_switch_collector.py:375)
- Show run command is `show running-config` for both VSP and ERS

### Hostname Detection Strategy
The script uses a multi-stage approach for hostname detection:
1. Query device directly using device-specific commands (most reliable)
2. Parse from `show running-config` output as fallback
3. Multiple regex patterns handle different output formats (extreme_switch_collector.py:245-277)

## Error Handling

### Command Execution Retry Logic
`send_command_with_retry()` implements a three-tier fallback strategy for handling large outputs or pattern detection failures:
1. Standard `send_command` with explicit prompt pattern
2. Retry with increased timeout and different strip settings
3. Timing-based method (`send_command_timing`) as last resort for outputs with paging issues

### Connection Handling
- Credentials are tested on first switch before bulk collection to prevent account lockout (extreme_switch_collector.py:556-559)
- Failed connections are automatically retried once (extreme_switch_collector.py:359)
- Failed switches are logged to `failed_switches.txt` for manual review

## Dependencies

```bash
pip install -r requirements.txt
```

Only dependency: `netmiko>=4.6.0`

## Switch Inventory Parser Details

### CSV Output Format
The inventory parser creates CSV files with the following columns:
- **Device**: Switch hostname
- **Port**: Interface number (e.g., 1/47)
- **Transceiver**: Physical transceiver type (1000BaseTX, GbicSx, GbicOther, etc.)
- **Model**: Connected device model from LLDP SysDescr
- **To Device**: Connected device hostname (from LLDP SysName or port description)
- **Native VLAN**: Untagged VLAN from default-vlan-id configuration
- **VLAN**: Space-separated list of tagged VLANs
- **Access**: VLAN mode (Access or Tagged)
- **Port-Channel**: MLT identifier if port is in a port-channel (e.g., MLT-11)
- **To Device IP**: IP address from LLDP neighbor data

### Data Sources and Parsing Logic
The parser combines data from multiple sources:

**From show_commands.txt:**
1. `show interfaces gigabitethernet` - Port status, speed, duplex, transceiver type, MLT assignments
2. `show pluggable-optical-modules basic` - Detailed transceiver information (vendor, part number, DDM support)
3. `show lldp neighbor` - Connected device hostname, model, and IP address

**From show_run.txt:**
1. Interface configurations - Port names/descriptions (alternative to LLDP for device names)
2. `default-vlan-id` commands - Native VLAN assignments
3. `vlan members` commands - Tagged VLAN memberships

### Site Identifier Extraction
Hostnames follow pattern: `LOCATION-SITE-BUILDING-TYPE-UNIT`
- Example: `INEVA-NSX-11IDF-SSW-00-A` → Site identifier: `NSX`
- Site identifier is the second dash-separated segment
- All switches from same site are combined into one CSV file

### Port Filtering
Only ports with operational status "up" are included in the CSV output. This excludes:
- Administratively down ports
- Unused/disconnected ports
- Failed or error-disabled ports

## Key Design Patterns

1. **Device-specific command mapping** - Different show commands and patterns for VSP vs ERS vs EXOS platforms
2. **Structured output organization** - Files organized by switch type in subdirectories
3. **Site-based aggregation** - Inventory parser groups switches by site identifier for simplified reporting
4. **Comprehensive logging** - Both console output (INFO level) and detailed file logs (DEBUG level when --debug flag used)
5. **Credential safety** - Test-before-proceed pattern prevents account lockout
6. **Graceful degradation** - Missing show command files or failed individual commands don't stop overall collection
