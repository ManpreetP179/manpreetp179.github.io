from sklearn.neighbors import KNeighborsClassifier

def Nearest_Neighbour(feature_train, 
                      label_train, 
                      feature_validation, 
                      label_validation, 
                      task,
                      model_file):
    """The K-Nearest Neighbour classifier, used with a featured analysis to
       try to predict the values
    Args:
        feature_train (_type_): the feature training set values
        label_train (_type_): the label training set values
        task (_type_): the feature that is being trained to be predicted
        selected_features (_type_): the features that were selected by the feature analysis
    """
    if model_file is None:
        knn = KNeighborsClassifier()
        knn.fit(feature_train, label_train)
        return knn
    
    return model_file