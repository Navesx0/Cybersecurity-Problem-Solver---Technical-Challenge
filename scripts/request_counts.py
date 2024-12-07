import pandas as pd
import matplotlib.pyplot as plt
import ipaddress
import numpy as np

# Load the dataset
file_path = './csv/test-dataset.csv'
network_data = pd.read_csv(file_path)

# Function to check if an IP is from the extranet
def is_extranet(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast
        )
    except ValueError:
        return False

# Filter extranet requests
extranet_requests = network_data[network_data['ClientIP'].apply(is_extranet)]

# Count number of requests per IP
ip_request_counts = extranet_requests['ClientIP'].value_counts()

# Detect outliers using the IQR method
q1 = ip_request_counts.quantile(0.25)
q3 = ip_request_counts.quantile(0.75)
iqr = q3 - q1

# Outlier threshold (IPs with traffic significantly higher than the median)
lower_bound = q1 - 1.5 * iqr
upper_bound = q3 + 1.5 * iqr

# Filter IPs that are outside the normal range (outliers)
potential_attackers = ip_request_counts[ip_request_counts > upper_bound]

# Save the list of potentially malicious IPs to a CSV file
output_file_path = './csv/request_counts.csv'
potential_attackers.to_csv(output_file_path, header=True)
