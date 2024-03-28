from sklearn.ensemble import GradientBoostingClassifier

def classify_GradientBoost(feature_training_set, target_training_set, task, model=None):
	if model is None:
		gbc = GradientBoostingClassifier()
		gbc.fit(feature_training_set, target_training_set)
	else:
		gbc = model
	return gbc