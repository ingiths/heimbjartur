import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Read the data from a CSV file
df = pd.read_csv('test_count.csv', delimiter=';')

# Extract the columns
test_count = df['Test Count']
time_ms = df['Time(ms)']

# Custom x-axis tick labels
x_labels = ['10^5', '10^6', '2·10^6', '3·10^6', '4·10^6', '5·10^6', '6·10^6', '7·10^6', '8·10^6', '9·10^6', '10^7']

# Set Seaborn style
sns.set_style("whitegrid")

# Create a Seaborn plot
plt.figure(figsize=(7, 5))
sns.lineplot(x=test_count, y=time_ms, marker='o', color='b', label='Time (ms)')
plt.title('Test evaluation performance')
plt.xlabel('Test Count')
plt.ylabel('Time (ms)')

# Set the custom x-axis tick labels
plt.xticks(test_count, labels=[f"{int(req/1e6)}M" for req in test_count])

plt.legend()

plt.grid(True, linestyle='--', alpha=0.6)

plt.savefig('performance.pdf', format='pdf', dpi=300)
