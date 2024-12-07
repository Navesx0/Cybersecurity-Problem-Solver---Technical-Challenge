import pandas as pd
import matplotlib.pyplot as plt

# Load the data from the CSV file
file_path_requests = './csv/test-dataset.csv'
data = pd.read_csv(file_path_requests, encoding='utf-8')

# Checking the first few rows to validate the data
print(data.head())

# Analyzing the 'ClientRequestUserAgent' field
# Total number of unique User Agents
user_agent_counts = data['ClientRequestUserAgent'].value_counts()

print(f'\nTotal number of unique User Agents: {len(user_agent_counts)}')

# Filtering the most common User Agents (e.g., top 10)
top_user_agents = user_agent_counts.head(10)

print(f'\nThe 10 most common User Agents:')
print(top_user_agents)

# Plotting the top 10 User Agents
plt.figure(figsize=(12, 6))
top_user_agents.plot(kind='bar', color='orange')
plt.title('Top 10 Most Common User Agents in Traffic')
plt.xlabel('User Agent')
plt.ylabel('Number of Requests')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# Identifying User Agents with suspicious patterns
# For example, User Agents that appear very frequently might be associated with bots
threshold = 80  # Setting an arbitrary threshold for "high frequency"
suspicious_user_agents = user_agent_counts[user_agent_counts > threshold]

print(f'\nUser Agents with more than {threshold} requests (potential attack patterns):')
print(suspicious_user_agents)

# Saving the suspicious User Agents to a CSV file
suspicious_user_agents.to_csv('./csv/suspicious_user_agents.csv', header=['RequestCount'])