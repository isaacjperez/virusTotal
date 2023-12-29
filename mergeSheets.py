# This script takes the pcap csv and merges it with the virus total results from the main.py.
# The output applies the verdict, verdict count, as owner and last analysis date to the corresponding IP in the pcap csv


import pandas as pd


def merge_and_update(pcap, vt_results, output_file):
    # Load your pcap csv and virus total results with IP addresses into two DataFrames (one for each sheet)

    # Read dataframes without specifying specific columns
    df_sheet1 = pd.read_csv(pcap)
    df_sheet2 = pd.read_csv(vt_results)

    # Create mapping dictionaries from 'IP Address' to 'Virus Total Verdict' and 'as_owner' in df_sheet2
    verdict_mapping = dict(zip(df_sheet2['IP Address'], df_sheet2['Virus Total Verdict']))
    as_owner_mapping = dict(zip(df_sheet2['IP Address'], df_sheet2['as_owner']))
    verdict_count_mapping = dict(zip(df_sheet2['IP Address'], df_sheet2['Verdict Count']))
    last_analysis_date_mapping = dict(zip(df_sheet2['IP Address'], df_sheet2['Last Analysis Date']))

    # Update 'Virus Total Verdict' and 'as_owner' in pcap_excel based on the matched rows
    df_sheet1['Virus Total Verdict'] = df_sheet1['Source'].map(verdict_mapping).combine_first(
        df_sheet1['Destination'].map(verdict_mapping))

    df_sheet1['as_owner'] = df_sheet1['Source'].map(as_owner_mapping).combine_first(
        df_sheet1['Destination'].map(as_owner_mapping))

    df_sheet1['Verdict Count'] = df_sheet1["Source"].map(verdict_count_mapping).combine_first(
        df_sheet1['Destination'].map(verdict_count_mapping))

    df_sheet1['Last Analysis Date'] = df_sheet1["Source"].map(last_analysis_date_mapping).combine_first(
        df_sheet1['Destination'].map(last_analysis_date_mapping))

    # Save the updated DataFrame to a new Excel file with two sheets

    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        df_sheet1.to_excel(writer, sheet_name='Sheet1', index=False)
        df_sheet2.to_excel(writer, sheet_name='Sheet2', index=False)

    print(f"Updated results saved to: {output_file}")
