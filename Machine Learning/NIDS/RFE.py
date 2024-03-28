from sklearn.tree import DecisionTreeClassifier
from sklearn.feature_selection import RFE
from graph import GraphGenerator


def recursive_feature_elimination(feature_training_set, feature_validation_set, target_training_set, task):
    """
    This function uses the Recursive Feature Elimination (RFE) method to select the best features for the model.
    :param feature_training_set:
    :param feature_test_set:
    :param target_training_set:
    :param task:
    :return: The selected features
    """

    clf = DecisionTreeClassifier()

    # Initialize RFE
    rfe = RFE(estimator=clf, n_features_to_select=12)

    rfe.fit(feature_training_set, target_training_set[task])

    selected_features = feature_training_set.columns[rfe.support_]
    
    rankings = rfe.ranking_
    
    graph = GraphGenerator(task)
    graph.generate_RFE_Graph(feature_training_set.columns, rankings)

    return selected_features
