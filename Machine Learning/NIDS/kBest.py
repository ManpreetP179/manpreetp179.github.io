from sklearn.feature_selection import mutual_info_classif
from sklearn.feature_selection import SelectKBest
from graph import GraphGenerator

def kBest(feature, feature_test, label, task):
    """This is a method that performs the SelectKBest function using the
        mutual information scoring function to find the k best features out of
        all of the columns in the data set.

    Args:
        feature (List): a list of features that are used to be trained
        label (List): a list of labels that are used to be trained
        task (str): the feature that is being trained to predict

    Returns:
        Index: a pandas Index Object of the selected features after the coorelation feature analysis is done.
    """
    label = label[task]
    
    # Performs SelectKBest to get the top k features from a training set using
    # the mutual_info_classif as a scoring function.
    selection = SelectKBest(mutual_info_classif, k=10).fit(feature, label)
        
    # Returns a boolean list of either true or false. If a feature was selected
    # as one of the top k features then it will be true, else it will return false.
    checked = selection.get_support(1) 
    # Will create a list of all items from the featured columns that were marked as
    # true.
    selected_features = feature_test.columns[checked]
    
    scores = selection.scores_
    feature_names = feature.columns
    
    graph = GraphGenerator(task)
    graph.generate_Kbest_Graph(scores, feature_names)
    
    return selected_features