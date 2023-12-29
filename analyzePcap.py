# this is the final product.
# the output is the pcap as a csv with the following columns:
# Source, Destination, Protocol, Src port, Dst port, Virus Total Verdict, as owner, verdict count, last analysis date
# and connection count.
# this does not include private to private connections.

import pandas as pd
import ipaddress


def analyze_pcap_data(merged_file, output_file):
    # Load the merged DataFrame with updated information
    # output of mergedSheet.py

    df_sheet1 = pd.read_excel(merged_file, sheet_name='Sheet1')

    # Define a function to check if an IP address is private
    def is_private(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    # Fill missing values in 'Last Analysis Date' with a default value (e.g., 'Unknown')
    # If there is no lat analysis date those rows will be dropped, so it assigned Unknown.
    df_sheet1['Last Analysis Date'] = df_sheet1['Last Analysis Date'].fillna('Unknown')

    # Filter rows with private IP addresses in either 'Source' or 'Destination'
    private_ip_connections = df_sheet1[
        (df_sheet1['Source'].apply(is_private)) |
        (df_sheet1['Destination'].apply(is_private))
        ]

    # Group by private IP addresses, port, protocol, and Virus Total Verdict, and count the number of connections
    # Add or remove columns that are present in the pcap csv
    grouped_data = private_ip_connections.groupby(
        ['Source', 'Destination', 'Protocol', 'Src port', 'Dst port', 'Virus Total Verdict', 'as_owner',
         'Verdict Count', 'Last Analysis Date']).size().reset_index(name='Connection Count')

    # Print the analysis results with all columns from 'Sheet1'
    print("Assets reaching out to private IP addresses:")
    print(grouped_data)

    # Save the analysis results to a new Excel file
    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        grouped_data.to_excel(writer, sheet_name='AnalysisResults', index=False)

    print(f"Analysis results saved to: {output_file}")

# Call the analysis function
# analyze_pcap_data()
