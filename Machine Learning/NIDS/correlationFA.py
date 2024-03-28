from graph import GraphGenerator
# Correlation Feature Analysis
# Uses the pandas feature correlation function to compute correlation scores for features. Highly correlated features will be removed, since we don't need "duplicates"

# https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.corr.html
def feature_select_CA(feature_training_set, feature_test_set, target_training_set, task):

	correlations = feature_training_set.corr()
	if task == 'Label':
		max_correlation = 0.75
	else:
		max_correlation = 0.798

	# https://stackoverflow.com/questions/29294983/how-to-calculate-correlation-between-all-columns-and-remove-highly-correlated-on 
	print("max correlation: " + str(max_correlation))
	all_columns = set()
	remove_columns = set()
	for i in range(len(correlations.columns)):
		for j in range(i):
			if (abs(correlations.iloc[i, j]) > max_correlation):
				if(j not in remove_columns):
					#print("BAD! correlation of " + str(i) + " and " + str(j) + " = " + str(abs(correlations.iloc[i, j]))) # enable this line to print all of the correlations we're getting rid of
					remove_columns.add(i)
		all_columns.add(i)


	keep_columns = [i for i in all_columns if i not in remove_columns]

	selected = feature_training_set.columns[keep_columns]
	
	print("columns removed: " + str(remove_columns.__len__()))

	graph = GraphGenerator(task)
	graph.generate_CA_Graph(correlations)

	return selected