"""
Convert switch_types.txt to switches.csv
- Column 1: IP address
- Column 2: Switch type (Core if "VSP" in name, otherwise IDF)
"""

import csv


def convert_switch_types(input_file='switch_types.txt', output_file='switches.csv'):
    """
    Convert switch_types.txt to switches.csv format.

    Args:
        input_file: Path to input tab-delimited file
        output_file: Path to output CSV file
    """
    switches = []
    skipped = []

    print(f"Reading from: {input_file}")

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Skip header line
    for i, line in enumerate(lines[1:], start=2):
        line = line.strip()
        if not line:
            continue

        # Split by tab
        parts = line.split('\t')

        if len(parts) >= 2:
            ip_address = parts[0].strip()
            machine_type = parts[1].strip()

            # Determine switch type based on presence of "VSP" in machine type
            if 'VSP' in machine_type.upper():
                switch_type = 'Core'
            else:
                switch_type = 'IDF'

            switches.append({
                'ip_address': ip_address,
                'switch_type': switch_type,
                'original_type': machine_type  # For reference
            })

            print(f"  Line {i}: {ip_address} -> {switch_type} ({machine_type})")
        else:
            skipped.append(f"Line {i}: Could not parse - {line}")

    # Write to CSV
    print(f"\nWriting to: {output_file}")
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['ip_address', 'switch_type']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for switch in switches:
            writer.writerow({
                'ip_address': switch['ip_address'],
                'switch_type': switch['switch_type']
            })

    # Summary
    print("\n" + "="*80)
    print("CONVERSION SUMMARY")
    print("="*80)
    print(f"Total switches processed: {len(switches)}")

    core_count = sum(1 for s in switches if s['switch_type'] == 'Core')
    idf_count = sum(1 for s in switches if s['switch_type'] == 'IDF')

    print(f"  Core switches: {core_count}")
    print(f"  IDF switches: {idf_count}")

    if skipped:
        print(f"\nSkipped lines: {len(skipped)}")
        for skip in skipped:
            print(f"  {skip}")

    print(f"\nOutput saved to: {output_file}")
    print("="*80)


if __name__ == "__main__":
    convert_switch_types()
