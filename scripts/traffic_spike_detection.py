import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler

# Load the CSV
csv_file = "./csv/test-dataset.csv" 
df = pd.read_csv(csv_file)

# Convert the timestamp to datetime and ensure it is in UTC
df['EdgeStartTimestamp'] = pd.to_datetime(df['EdgeStartTimestamp']).dt.tz_convert('UTC')

# 1. Aggregate requests by time interval (e.g., 1 minute)
df.set_index('EdgeStartTimestamp', inplace=True)
df_resampled = df.resample('1min').size()  # Resample by minute (adjustable)

# 2. Traffic spike detection using normalization
scaler = StandardScaler()
df_resampled_scaled = scaler.fit_transform(df_resampled.values.reshape(-1, 1))

# Standard deviation threshold to detect spikes (adjustable)
threshold = 3  
spikes = df_resampled_scaled > threshold

# Identify timestamps with spikes
spike_times = df_resampled.index[spikes.flatten()]

# Display detected spikes
print("\nSuspicious traffic spikes detected:")
print(spike_times)

# 3. Cross-reference IPs that contributed most to the detected spikes
suspects = []

for spike in spike_times:
    start = spike
    end = spike + pd.Timedelta(minutes=1)

    # Filter requests during the spike minute using between
    spike_period = df.loc[df.index.to_series().between(start, end)]
    
    # Count requests by IP during the period
    ip_counts = spike_period['ClientIP'].value_counts()
    
    # Display the most active IPs during the spike period
    top_ips = ip_counts.head(10)  # Adjustable for more IPs
    print(f"\nSpike at {spike}:")
    print(top_ips)
    
    # Store suspect IPs
    suspects.extend(top_ips.index)

# 4. Count the frequency of each suspect IP
suspect_ip_count = pd.Series(suspects).value_counts()

# Export suspect IPs to CSV
suspect_ip_count.to_csv("./csv/suspect_ddos_ips.csv", header=['Frequency'], index_label='ClientIP')
print("\nSuspect attack IPs exported to 'suspect_ddos_ips.csv'.")

# 5. Visualize traffic spikes
plt.figure(figsize=(12, 6))
plt.plot(df_resampled.index, df_resampled.values, label='Aggregated Traffic')
plt.scatter(spike_times, df_resampled[spike_times], color='red', label='Suspicious Spikes')
plt.title('Traffic Analysis - Suspicious Spikes (DDoS/DoS)')
plt.xlabel('Time')
plt.ylabel('Number of Requests')
plt.legend()
plt.show()
