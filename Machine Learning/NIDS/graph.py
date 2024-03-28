import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

class GraphGenerator:
    def __init__(self, task):
        self.task = task
    
    def generate_Kbest_Graph(self, scores, feature_names):
        # Plot the mutual information scores for the selected features
        fig, ax = plt.subplots(figsize=(12, 6))
        y_pos = np.arange(len(feature_names))
        ax.barh(y_pos, scores, align='center')
        ax.set_yticks(y_pos)
        ax.set_yticklabels(feature_names)
        ax.invert_yaxis()  # labels read top-to-bottom
        ax.set_xlabel('Mutual Information Score')
        ax.set_title(f'Mutual Information Scores for Features - {self.task}')
        plt.show()
        
    def generate_CA_Graph(self, corr):
        # Plotting for feature selection scores obtained from feature_select_CA
        plt.figure(figsize=(12, 10))
        sns.heatmap(corr, annot=True, cmap='coolwarm', fmt=".2f", annot_kws={"size": 5})
        plt.title(f'Correlation Heatmap - {self.task}')
        plt.show()
        
    def generate_RFE_Graph(self, feature,rankings):
        plt.figure(figsize=(10, 6))
        plt.barh(range(len(rankings)), rankings, align='center')
        plt.yticks(np.arange(len(feature)), feature)
        plt.xlabel('Ranking')
        plt.ylabel('Features')
        plt.title(f'Feature Rankings - {self.task}')
        plt.show()