# depreciated
# whois info and DNS record are too inconsistent.
# from removeDuplicates import input_csv

'''


import whois
import socket
from ipwhois import IPWhois
import dns.reversename

def getCreationDate(IP):
    # Perform reverse DNS lookup
    try:
        # get the domain using the IP address.
        hostnames = socket.gethostbyaddr(IP)
        print("host names ", hostnames)
    # DNS look up failed
    except socket.herror as e:
        print("Reverse DNS Lookup failed: {}".format(e))
        return "Reverse DNS Lookup Failed"

    try:
        # first item in the array is the domain name.
        domain = hostnames[0]
        print(domain)

        whois_info = whois.query(domain)
        registrar = whois_info.registrar
        print(registrar)

        # domain creation date
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):
            # For some domains, creation_date may be a list of dates
            creation_date = creation_date[0]
        # Format the datetime object as a string with only year-month-date
        formatted_date = creation_date.strftime('%Y-%m-%d')
        # print(formatted_date)
        return formatted_date
    except:
        # the domain can't be processed, not valid.
        print("error")
        return "error"


# Note: Some information may not be available for all IP addresses


'''