from removeDuplicates import extract_and_filter_ips
from getVirusTotalVerdict import get_verdict
from mergeSheets import merge_and_update
from analyzePcap import analyze_pcap_data

# This script utilizes the virus total community API and is limited to 500 request per day.

# STEP 1) save pcap as a csv file
# pcap must have columns named Src port and Dst port
# if not then they must be removed from analyzePcap.py
# link to article on how to add columns in wireshark
# https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/

# path to pcap as a csv
csv_pcap = ''

# STEP 2) remove duplicates and private IP addresses so that they can be run through virus total.

# input is the pcap csv step 1.
# output file path for removeDuplicates
# must be csv
unique_non_private_IP_addresses = ''

# STEP 3) get virus total info
# input is the output of removeDuplicates step 2.

# output path for virus total results
# must be csv
virus_total_results = ""

# STEP 4) merge virus total results wth pcap csv
# takes two inputs: the pcap csv from step 1 and the virus total results from step 3.
# the output is an Excel file with two pages.
# the first sheet the pcap with all the VT info.
# the second sheet shows only unique non-private IPs with VT info

# path to output of merge_and_update
# must be .xlsx file
merged_file = ''

# STEP 5) analyze pcap
# input is the merged file from step 4.
# output is the final product.
# the output is the pcap as a csv with the following columns:
# Source, Destination, Protocol, Src port, Dst port, Virus Total Verdict, as owner, verdict count, last analysis date
# and connection count.
# this does not include private to private connections.

# output path for analyze_pcap_data
# can be csv or xlsx
analysis_output_path = ''


def main():
    extract_and_filter_ips(csv_pcap, unique_non_private_IP_addresses)
    get_verdict(unique_non_private_IP_addresses, virus_total_results)
    merge_and_update(csv_pcap, virus_total_results, merged_file)
    analyze_pcap_data(merged_file, analysis_output_path)


if __name__ == "__main__":
    main()
