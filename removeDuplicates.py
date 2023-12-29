# This script takes a pcap as a csv and removes the private IP addresses and duplicate IP address.
# It outputs the results as a CSV with a single column named IP address.


import pandas as pd
import ipaddress


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        # Handle invalid IP addresses
        return False


def extract_and_filter_ips(input_csv, output_csv):
    # Read the CSV file into a pandas DataFrame
    df = pd.read_csv(input_csv)

    # Extract unique IP addresses from the "Source" and "Destination" columns
    unique_ips = pd.concat([df['Source'], df['Destination']]).unique()

    # Filter out private IP addresses
    filtered_ips = [ip for ip in unique_ips if not is_private_ip(ip)]

    # Create a new DataFrame with a single column named "IP Address"
    result_df = pd.DataFrame({'IP Address': filtered_ips})

    # Write the result DataFrame to a new CSV file
    result_df.to_csv(output_csv, index=False)

    print(f"Unique non-private IP addresses extracted from {input_csv} and saved to {output_csv}.")
