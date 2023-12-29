import requests
import csv
from datetime import datetime
# Your API key obtained from VirusTotal
from config import api_key

# Uses the community API
# Takes a single column CSV with a header.
# Outputs the IP with its Virus Total Verdict.
# This update provides the ASN owner, last analysis date, and verdict count to the results of the output.


# Your API Key.
# moved to config file.
# api_key = ""


# Define the base URL for the VirusTotal API
base_url = "https://www.virustotal.com/api/v3/ip_addresses/"

# Define the headers including your API key
headers = {
    "x-apikey": api_key,
    "accept": "application/json"
}


# Function to check an IP address using the VirusTotal API and determine its category
def check_ip_category(ip_address):
    url = f"{base_url}{ip_address}"
    response = requests.get(url, headers=headers, verify=False)  # added False because MAC was having trouble
    # verifying the cert. No issue on Windows.

    if response.status_code == 200:  # response code 200 means no error.
        # Access nested dictionary
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})

        # totaling verdict counts
        total = 0

        for value in last_analysis_stats:
            total += last_analysis_stats[value]

        # Check for virus total verdict.

        if "malicious" in last_analysis_stats and last_analysis_stats["malicious"] > 0:
            return (
                "malicious", str(last_analysis_stats["malicious"]) + " of " + str(total),
                attributes.get("as_owner", ""),
                attributes.get("last_analysis_date", ""),  # getCreationDate(ip_address)
            )
        elif "suspicious" in last_analysis_stats and last_analysis_stats["suspicious"] > 0:
            return (
                "suspicious", str(last_analysis_stats["suspicious"]) + " of " + str(total),
                attributes.get("as_owner", ""),
                attributes.get("last_analysis_date", ""),  # getCreationDate(ip_address)
            )
        elif "harmless" in last_analysis_stats and last_analysis_stats["harmless"] > 0:
            return (
                "harmless", str(last_analysis_stats["harmless"]) + " of " + str(total), attributes.get("as_owner", ""),
                attributes.get("last_analysis_date", ""),  # getCreationDate(ip_address)
            )
        else:
            return (
                "unrated", str(last_analysis_stats["undetected"]) + " of " + str(total), attributes.get("as_owner", ""),
                attributes.get("last_analysis_date", ""),  # getCreationDate(ip_address)
            )

    elif response.status_code == 404:
        return "not found", ""  # Treat 404 as "not found"
    else:  # error for when I have hit my quota.
        print(f"Error for IP {ip_address}: {response.status_code} - {response.text}")
        return "error", ""


# Function to read IP addresses from a CSV file, skips the header.
def read_ip_addresses_from_csv(csv_filename):
    ip_addresses = []
    with open(csv_filename, "r", newline="") as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header row
        for row in reader:
            if row:  # Check if the row is not empty
                ip_addresses.append(row[0])  # Assuming the IP address is in the first column
    return ip_addresses


# Main function to check IP addresses from a CSV file and generate a new file
def get_verdict(csv_filename, output):
    ip_addresses = read_ip_addresses_from_csv(csv_filename)

    # Open the output file for writing
    with open(output, "w", newline="") as csvfile:
        fieldnames = ["IP Address", "Virus Total Verdict", "Verdict Count",
                      "as_owner", "Last Analysis Date"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip in ip_addresses:
            # add domain_date
            category, count, as_owner, date, = check_ip_category(ip)

            # if there is no last analysis date an empty string is returned and will cause an error.
            if date != "":
                date = datetime.utcfromtimestamp(date).strftime('%Y-%m-%d')

            writer.writerow({
                "IP Address": ip,
                "Virus Total Verdict": category,
                "Verdict Count": count,
                "as_owner": as_owner,
                "Last Analysis Date": date,
                # "Domain Creation Date": domain_date
            })

# get_verdict(IPs_to_be_checked, virus_total_results)
