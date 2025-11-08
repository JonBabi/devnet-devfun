# Credential Setup Guide

## Problem Solved
Previously, using `credentials.json` with passwords containing backslashes (`\`) or other special characters required escaping (e.g., `pass\\word`), which was error-prone.

## Solution
The script now supports three methods for credentials, with the simpler formats recommended:

### Method 1: credentials.env File (RECOMMENDED)
**Best for passwords with special characters - no escaping needed!**

1. Copy the example file:
   ```bash
   cp credentials.env.example credentials.env
   ```

2. Edit `credentials.env`:
   ```
   SWITCH_USERNAME=admin
   SWITCH_PASSWORD=my\pass/word$123!
   ```

**Advantages:**
- ✅ Works with backslashes: `\`
- ✅ Works with forward slashes: `/`
- ✅ Works with any special characters: `$`, `!`, `@`, `#`, etc.
- ✅ No escaping required
- ✅ Simple KEY=VALUE format

### Method 2: Environment Variables
**Best for automation and security**

```bash
export SWITCH_USERNAME=admin
export SWITCH_PASSWORD='my\pass/word$123!'
export SWITCH_ENABLE_PASSWORD='enable_password'  # Optional

python extreme_switch_collector.py
```

### Method 3: credentials.json (Still Supported)
**Backward compatible, but requires escaping**

```json
{
  "username": "admin",
  "password": "pass\\word"
}
```

⚠️ **Note:** Backslashes must be doubled: `\` becomes `\\`

## Testing Your Credentials

To verify your credentials are loaded correctly:

```bash
python extreme_switch_collector.py
```

The script will display which method it used:
- "Credentials loaded from environment variables"
- "Credentials loaded from credentials.env"
- "Credentials loaded from credentials.json"

## Priority Order
If multiple methods are configured, the script uses this priority:
1. Environment variables (highest priority)
2. credentials.env file
3. credentials.json file (lowest priority)

## Security
- The `.gitignore` file has been updated to exclude both `credentials.env` and `credentials.json`
- Never commit credential files to version control
- Use environment variables for production/automated deployments
