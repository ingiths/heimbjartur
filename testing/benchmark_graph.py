import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# df = pd.DataFrame(data)
df = pd.read_csv("benchmark.csv", delimiter=";")

# Melt the DataFrame so it's in long-form for Seaborn
df_melted = pd.melt(df, id_vars=['Packets'], var_name='Type', value_name='Time(ms)')

# Plotting with Seaborn
sns.set_theme(style="whitegrid")
plt.figure(figsize=(7, 5))

sns.lineplot(x='Packets', y='Time(ms)', hue='Type', data=df_melted, marker="o")

plt.title('eBPF performance penalty')
plt.xlabel('Number of packets')
plt.ylabel('Time(ms)')
plt.legend(title='eBPF State')
plt.xticks(df['Packets'], labels=[f"{int(req/1e6)}M" for req in df['Packets']])
plt.tight_layout()

plt.savefig('benchmark.pdf')

