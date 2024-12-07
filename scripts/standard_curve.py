import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import norm

# Load the CSV file with the correct encoding
file_path = './csv/request_counts.csv'
ip_data = pd.read_csv(file_path, encoding='utf-8')

# Calculate the mean and standard deviation
mean_requests = ip_data['count'].mean()
std_requests = ip_data['count'].std()

# Calculate the upper threshold of the normal curve (mean + 1.5 * standard deviation)
threshold_upper = mean_requests + 1.5 * std_requests

# Filter the IPs that are above the upper threshold (deviating upwards from the curve)
suspect_ips = ip_data[ip_data['count'] > threshold_upper]

# Display the upper threshold and suspect IPs
print(f'The upper threshold for deviating from the normal curve is: {threshold_upper}')
print("IPs deviating upwards from the normal curve (potential DDoS attacks):")
print(suspect_ips)

# Save the suspect IPs to a CSV file
output_file = './csv/suspect_ips_above_threshold.csv'
suspect_ips.to_csv(output_file, index=False)

# Confirm the file was saved
print(f'File with suspect IPs saved as: {output_file}')

# Generate values for the normal curve based on the mean and standard deviation
x_values = np.linspace(ip_data['count'].min(), ip_data['count'].max(), 1000)
y_values = norm.pdf(x_values, mean_requests, std_requests)

# Plot the histogram and the normal curve
plt.figure(figsize=(12, 6))

# Plotting the request histogram
plt.hist(ip_data['count'], bins=30, color='lightblue', edgecolor='black', alpha=0.7, density=True, label='Request Histogram')

# Plotting the normal curve based on the mean and standard deviation
plt.plot(x_values, y_values, color='red', label='Normal Curve')

# Plotting the mean and standard deviation limits
plt.axvline(mean_requests, color='green', linestyle='dashed', linewidth=2, label='Mean')
plt.axvline(threshold_upper, color='orange', linestyle='dashed', linewidth=2, label='Upper Threshold (1.5 std)')

# Highlight the suspect IPs with request counts above the upper threshold
plt.scatter(suspect_ips['count'], np.zeros(len(suspect_ips)), color='red', zorder=5, label='Suspect IPs')

# Adding title, labels, and legend
plt.title('Request Distribution, Normal Curve, and Suspect IPs')
plt.xlabel('Number of Requests')
plt.ylabel('Probability Density')
plt.legend()
plt.grid(True)

# Display the plot
plt.show()
