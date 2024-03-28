import warnings
warnings.filterwarnings("ignore")
import sys
import time

import numpy as np
import difflib as dlib

import sklearn.feature_selection
from sklearn.preprocessing import LabelEncoder
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
import sklearn.model_selection
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score, classification_report

import sklearn.tree
import sklearn.preprocessing
import pickle
import argparse
import pandas as pd

# Import Classifier Files
from decisionTree import decision_tree
from knearest import Nearest_Neighbour
from gaussianNB import classify_Gaussian_NB # GaussianNB Classifier
from gradientBoost import classify_GradientBoost

# Import feature analysis Files
from kBest import kBest
from RFE import recursive_feature_elimination
from correlationFA import feature_select_CA  # correlation feature selection

# sample program usage: python NIDS.py test_set.csv feature_analysis classifier task --model_to_load model_file

# feature selection
# Chris: Correlation Feature Analysis
# Manpreet: KBest-Mutual Information Analysis
# Joey: Recursive Feature Elimination

# list of classifiers in scikit-learn https://scikit-learn.org/stable/auto_examples/classification/plot_classifier_comparison.html
# Chris: Gaussian Naive-Bayes, Gaussian Boost
# Manpreet: K-Nearest Neighbour
# Joey: Decision Tree


# load or saved pickled model
# if a file is specified, it will be loaded, otherwise the filename will be assumed from the task and classifier
# if there's no model file and no pickle file to load, will return None. 
def loadModel(model_file):
    # if there's a model file, load and return it
    if model_file is None:
        return None
    with open(model_file, 'rb') as f:
        return pickle.load(f)
                
def saveModel(task, feature_selection, classifier, model):
    # Save the given model as task_model_classifier
    if feature_selection is None:
        feature_selection = 'None'

    with open('{0}_{1}_{2}.skl'.format(feature_selection, classifier, task), 'wb') as f:
        pickle.dump(model, f)

def preprocess_data(test_csv, columns):
    """This method preprocesses the datafram in order to allow for use in the featured analysis and
       training of the classifiers.

    Args:
        test_csv (File): The CSV file that will be used as the data set
        columns (List): The list of features in the csv file

    Returns:
        Dataframe: A dataframe object of all of the columns left after preprocessing
    """
    compare = []
    data = pd.read_csv(test_csv,
                       header=None,
                       names=columns,
                       skiprows=1)

    df = pd.DataFrame(data,
                      columns=columns)
    
    # delete the columns with null values
    del df['ct_flw_http_mthd']
    del df['is_ftp_login']
    del df['ct_ftp_cmd']

    # conversions
    df['proto']=pd.factorize(df['proto'])[0]
    df['state']=pd.factorize(df['state'])[0]
    df['dsport']=pd.factorize(df['dsport'])[0]
    df['srcip']=pd.factorize(df['srcip'])[0]
    df['sport']=pd.factorize(df['sport'])[0]
    df['dstip']=pd.factorize(df['dstip'])[0]
    df['dur']=pd.factorize(df['dur'])[0]
    df['service']=pd.factorize(df['service'])[0]

    df["service"].replace('-','None')
    df["attack_cat"].fillna('None', inplace = True)

    #preprocessing attack_cat for clones and similar words
    df["attack_cat"] = df["attack_cat"].str.strip()
    
    # Checks for copies of the same outputs
    df["attack_cat"] = df["attack_cat"].str.strip()
    
    # Grab a copy of every unqiue value in attack_cat
    unique = df["attack_cat"].unique()
    
    compare.append(unique[0])
    
    # For every unique value in attack_cat, find any values that are very similar to eachother
    # i.e. Backdoor and Backdoors and replace one of the values with the other
    for i in unique:
        matches = dlib.get_close_matches(i,
                                        compare,
                                        n=1,
                                        cutoff=0.8)
        if not matches:
            compare.append(i)
        else:
            df["attack_cat"] = df["attack_cat"].replace(i,
                                                        matches[0])

    # Factorize attack_cat afterwards
    df['attack_cat'] = pd.factorize(df['attack_cat'])[0]

    return df


def parse_arguments() -> None:
    parser = argparse.ArgumentParser(description='NIDS')

    parser.add_argument('test_set_csv', type=str, help='Path to the test set CSV file')
    parser.add_argument('feature_analysis', type=str, choices=['None', 'RFE', 'Correlation', 'KBest'],
                        help='Feature Analysis Type')
    parser.add_argument('classifier', type=str, choices=['decisionTree', 'gaussianNB', 'gradientBoost', 'kNearest'],
                        help='Classifier type')
    parser.add_argument('task', type=str, choices=['attack_cat', 'Label'], help='Task type')
    parser.add_argument('--model_to_load', dest='model', type=str, default=None,
                        help='Optional: Path to the model to load')

    start_time = time.time()

    args = parser.parse_args()

    if args.test_set_csv is None:
        print('Error: test_set_csv is required')
        sys.exit(1)
    if args.feature_analysis is None:
        print('Error: feature_analysis is required')
    if args.classifier is None:
        print('Error: classifier is required')
        sys.exit(1)
    if args.task is None:
        print('Error: task is required')
        sys.exit(1)

    # Selected_features is what will be chosen by the feature analysis technique to use as training columns
    selected_features = []

    test_cols = ['attack_cat', 'Label']

    # Includes all of the columns from the test file UNSW-NB15-BALANCED-TRAIN.csv
    all_columns = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'state',
                   'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
                   'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin',
                   'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth',
                   'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt',
                   'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
                   'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm',
                   'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label']

    # Excludes the columns: attack_cat, and Label from the original list
    # of columns in the test file, since these won't be used for featured selection.
    feature_cols = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'state',
                    'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
                    'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin',
                    'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth',
                    'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt',
                    'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports',
                    'ct_state_ttl', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
                    'ct_src_ ltm', 'ct_src_dport_ltm',
                    'ct_dst_sport_ltm', 'ct_dst_src_ltm']

    df = preprocess_data(args.test_set_csv, all_columns)

    # split data set into two - gives us 80% of the set as training, and 20% as validation
    feature_training_set, feature_validation_set, target_training_set, target_validation_set = train_test_split(
        df[feature_cols],
        df[test_cols],
        test_size=0.20,
        random_state=0)


    # Replace all unique categorical string values with a unique
    # numerical value instead. This will also keep the new Dataframe
    # in the same shape as the original one.
    feature_training_set.apply(LabelEncoder().fit_transform)

    feature_validation_set.apply(LabelEncoder().fit_transform)

    preprocessing.normalize(feature_training_set)
    
    # try loading a model
    # model functions should check for this value being None!
    initial_model = loadModel(args.model)

    # Random Forest feature selection
    if args.feature_analysis == 'RFE':
        selected_features = recursive_feature_elimination(feature_training_set,
                                                              feature_validation_set,
                                                              target_training_set,
                                                              args.task)
        
    # Correlation Feature Analysis
    elif args.feature_analysis == 'Correlation':
        selected_features = feature_select_CA(feature_training_set, 
                            feature_validation_set, 
                            target_training_set, 
                            args.task)
        
    # K-Best feature selection
    elif args.feature_analysis == 'KBest':
        selected_features = kBest(feature_training_set,  
                            feature_validation_set,
                            target_training_set, 
                            args.task)

    # no feature selection
    elif args.feature_analysis == 'None' or len(selected_features) == 0:
        selected_features = feature_cols

    # filter feature training, validation, and test sets down to only selected features
    feature_training_set = feature_training_set[selected_features]
    feature_validation_set = feature_validation_set[selected_features]
        
        
	# filter task training, validation, and test sets down to only selected task
    target_training_set = target_training_set[args.task]
    target_validation_set = target_validation_set[args.task]
        
    # Initialize the trained model variable
    trained_model = None

    # pick a classifier according to args and train the classifier model
    # Decision Tree classifier
    if args.classifier == 'decisionTree':
        trained_model = decision_tree(feature_training_set,
                                      target_training_set,
                                      feature_validation_set,
                                      target_validation_set,
                                      args.task,
                                      initial_model)
    # GaussianNB classifer
    elif args.classifier == 'gaussianNB':
        if args.task == 'attack_cat':
            label_model = classify_Gaussian_NB(feature_training_set, target_training_set, 'Label')
            label_training_predictions = label_model.predict(feature_training_set)
            label_validation_predictions = label_model.predict(feature_validation_set)
            feature_training_set['Label'] = label_training_predictions
            feature_validation_set['Label'] = label_validation_predictions
        trained_model = classify_Gaussian_NB(feature_training_set, target_training_set, args.task, initial_model)
        
    # GradientBoost Classifier  
    elif args.classifier == 'gradientBoost':
        trained_model = classify_GradientBoost(feature_training_set, target_training_set, args.task, initial_model)
    
    # k-Nearest-Neighbors Classifier
    elif args.classifier == 'kNearest':
        trained_model = Nearest_Neighbour(feature_training_set,
                          target_training_set,
                          feature_validation_set,
                          target_validation_set,
                          args.task,
                          initial_model)

    # save the model - will overwrite by default
    if initial_model is None:
        saveModel(args.task, args.feature_analysis, args.classifier, trained_model)

    # use the trained model to make the predictions we're interested in
    prediction_array = trained_model.predict(feature_validation_set)

    # do metrics on the model's predictions
    confusion_matrix(target_validation_set, prediction_array)
    accuracy_score(target_validation_set, prediction_array)
    micro_f1 = f1_score(target_validation_set, prediction_array, average='micro')
    macro_f1 = f1_score(target_validation_set, prediction_array, average='macro')

    # Get the elapsed time of training a model
    elapsed_time = time.time() - start_time

    # print the metrics
    print('Feature Selection: ' + args.feature_analysis)
    print('Classifier: ' + args.classifier)
    print(classification_report(target_validation_set, prediction_array))
    print("Micro F1 Score: ", micro_f1)
    print("Macro F1 Score: ", macro_f1)
    print(f"Elapsed Time:  {elapsed_time:.1f} seconds")

def main():
    parse_arguments()

if __name__ == "__main__":
    main()
