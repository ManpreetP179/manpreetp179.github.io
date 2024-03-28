from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import GridSearchCV
# Gaussian Naive-Bayes Classifier
# https://scikit-learn.org/stable/modules/generated/sklearn.naive_bayes.GaussianNB.html

# Uses a pairwise sum-of-squares method for combining datasets (Gaussian) and a naive version of Bayes' theorem
# https://scikit-learn.org/stable/modules/naive_bayes.html#gaussian-naive-bayes

# Parameters: 
# 	priorsarray-like of shape (n_classes,), default=None Prior probabilities of the classes. If specified, the priors are not adjusted according to the data.
# 	var_smoothing float, default=1e-9 Portion of the largest variance of all features that is added to variances for calculation stability.

# Attributes:
#	class_count_ndarray of shape (n_classes,) number of training samples observed in each class.
# 	class_prior_ndarray of shape (n_classes,) probability of each class.
# 	classes_ndarray of shape (n_classes,) class labels known to the classifier.
# 	epsilon_float absolute additive value to variances.
# 	n_features_in_int Number of features seen during fit.
# 	feature_names_in_ndarray of shape (n_features_in_,) Names of features seen during fit. Defined only when X has feature names that are all strings.
# 	var_ndarray of shape (n_classes, n_features) Variance of each feature per class.
# 	theta_ndarray of shape (n_classes, n_features) mean of each feature per class.

def classify_Gaussian_NB(feature_training_set, target_training_set, task, model=None):
	if model is None:
		gnb = GaussianNB()
		parameters = {'priors': [None], 'var_smoothing': [0.00000001, 0.000000001, 0.00000001, 0.000000001, 0.0000000001, 0.00000000001, 0.000000000001, 0.0000000000001, 0.00000000000001, 0.000000000000001, 0.0000000000000001, 0.00000000000000001, 0.000000000000000001, 0.0000000000000000001, 0.00000000000000000001, 0.000000000000000000001, 0.0000000000000000000001, 0.00000000000000000000001, 0.000000000000000000000001, 0.0000000000000000000000001] }

		#gscv = GridSearchCV(gnb, parameters)
		gscv = GaussianNB()
		gscv.fit(feature_training_set, target_training_set)
	else:
		gscv = model
	return gscv