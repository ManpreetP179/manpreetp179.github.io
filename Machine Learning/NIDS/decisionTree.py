from sklearn.tree import DecisionTreeClassifier


def decision_tree(feature_training_set, target_training_set, feature_validation_set, target_validation_set, task,
                  model):
    """
    Main function for decisionTree.py
    :param feature_training_set: The feature training set
    :param target_training_set: The target training set
    :param feature_validation_set: The feature validation set
    :param target_validation_set: The target validation set
    :param task: The task that is being trained to be predicted
    :param model: The model file
    :return: The trained model
    """

    if model:
        # Model exists, load it
        return model
    else:
        # Model doesn't exist

        # Initialize decision tree classifier with default parameters
        clf = DecisionTreeClassifier(max_depth=15)

        # Train the classifier using the training data
        clf.fit(feature_training_set, target_training_set)

        return clf
