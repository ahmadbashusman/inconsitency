import matplotlib
#matplotlib.use("TkAgg")      # or "Qt5Agg", if you have PyQt5/PySide2 installed
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd




# Load dataset from CSV
dataset = pd.read_csv("./csv/cve_vendor_fw.csv")



# Set the size of the figure
#plt.figure(figsize=(3.5, 4.8))  # Adjust the figure size as needed

# Create the box plot
sns.set_theme(style="whitegrid")


#sns.violinplot(data=dataset, x='year',  y='base', hue='type')

#sns.boxplot(data=dataset, x='year', y='base', hue='type')
#sns.boxenplot(data=dataset, x='year', y='base', hue='type')

sns.stripplot(data=dataset, x='year', y='base', hue='type', palette={'CVE': '#A0522D', 'vendor': '#FFD700'}, hue_order=['CVE', 'vendor'], dodge=True, jitter=True)
#sns.swarmplot(data=dataset, x='year', y='base', hue='type')








# Customize the legend
plt.legend(title='')
plt.xlabel('')
plt.ylabel('Base Score')
plt.title('Firmware update vulnerability distribution')
plt.legend(loc='lower center')



# Save the plot as a PDF
plt.savefig("./figures/base_violin_plot_new.pdf", format='pdf' ,bbox_inches='tight')
#plt.savefig("impact_violin_plot_new.pdf", format='pdf' ,bbox_inches='tight')
#plt.savefig("exploitability_violin_plot_new.pdf", format='pdf' ,bbox_inches='tight')

# Show the plot
#plt.show()