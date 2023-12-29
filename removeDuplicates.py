import pandas as pd
import ipaddress


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        # Handle invalid IP addresses
        return False


def extract_and_filter_ips(*input_files, output_csv):
    # Read the CSV files into a pandas DataFrame

    df_list = [pd.read_csv(file) for file in input_files]
    df = pd.concat(df_list)

    # Extract unique IP addresses from the "Source" and "Destination" columns

    unique_ips = pd.concat([df['Source'], df['Destination']]).unique()

    # Filter out private IP addresses
    filtered_ips = [ip for ip in unique_ips if not is_private_ip(ip)]

    print(f'There are {len(filtered_ips)} unique IPs')

    # Prompt user for confirmation
    while True:
        user_input = input("Do you want to continue? (yes/no): ").lower()
        if user_input == 'yes':
            break
        elif user_input == 'no':
            print("Exiting the program.")
            exit()
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

    # Create a new DataFrame with a single column named "IP Address"
    result_df = pd.DataFrame({'IP Address': filtered_ips})

    # Write the result DataFrame to a new CSV file
    result_df.to_csv(output_csv, index=False)

    print(f"Unique non-private IP addresses extracted from {input_files} and saved to {output_csv}.")


