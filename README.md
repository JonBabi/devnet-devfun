# Work Projects Repository

This repository contains various work-related projects and automation scripts.

## Directory Structure

### Jobs/Open/Ascension/Evansville/
Network automation toolkit for collecting and parsing configuration data from Extreme Networks switches.

- **extreme_switch_collector.py** - Main data collection script for Core (VSP) and IDF (ERS) switches
- **parse_lldp_neighbors.py** - LLDP neighbor parser
- **parse_switch_inventory.py** - Switch inventory parser
- **convert_switch_types.py** - Inventory converter

See the `CLAUDE.md` file in the Evansville directory for detailed project documentation.

### AI Training/ClaudCode/Projects/
Claude Code training projects and examples.

## Setup

For the Extreme Networks project:
```bash
cd "Jobs/Open/Ascension/Evansville"
pip install -r requirements.txt
```

Refer to project-specific documentation in each directory for detailed instructions.
