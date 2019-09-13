#!/usr/bin/python

"""

File:        cmpsc443-ids.py
Descruption: This is the implementation of the 443 IDS system.
Author:      Alina Aftab
Date:        12.04.2018

"""

# Import statements 
import csv
import matplotlib.pyplot as plt
import numpy as np

# Global data
ids_training_data = []
ids_testing_data = []
total_positives = 0
total_negatives = 0

# Read the training and test data
def readIDSData():

	# Variables
	global ids_training_data, ids_testing_data

	# Read the training data file
	fdesc = open("cmpsc443-ids-training.csv", "rt")
	datreader = csv.reader(fdesc, delimiter=',')
	for row in datreader:
		ids_training_data.append( [int(row[0]), int(row[1]), int(row[2]), int(row[3]), int(row[4]), int(row[5])] )

	# Read the testing data file (ONLY NEEDED FOR HONORS OPTION)
	fdesc = open("cmpsc443-ids-testing.csv", "rt")
	datreader = csv.reader(fdesc, delimiter=',')
	for row in datreader:
		ids_testing_data.append( row );

#finds the total number of malicious and non maliciouf flow
def find_total():
	global total_positives
	global total_negatives
	for x in ids_training_data:
		if x[5] == 1:
			total_positives = total_positives +1
		else:
			total_negatives = total_negatives+1

#finds sum excluding the feature 
def find_sum_of_features(excluded_feature, item):
	sum = 0
	for y in range(0,5):
		if(y != excluded_feature):
			sum = sum + item[y]
	return sum

#returns fpr rate
def get_fpr(fp):
	return 100*(fp/total_negatives)

#returns tpr rate
def get_tpr(tp):
	
	return 100*(tp/total_positives)

#finds the plot points for the graph for each cruve
def algorithm(excluded_feature):
	global ids_training_data
	
	fp = 0.0
	tp = 0.0
	tpr = []
	fpr = []	

	for threshhold in range(0, 300):
	
		for x in ids_training_data:
			#if malicious
			if find_sum_of_features(excluded_feature, x)>=threshhold:
				#if makrked  1 add 1 t0 TP
				if x[5] == 1:
					tp = tp+1.0
				#else add 1 to FP
				else:
					fp = fp+1.0
		#add to array
		tpr.append(get_tpr(tp))
		fpr.append(get_fpr(fp))
		#reset TP and FP for every threshhold
		tp = 0.0
		fp = 0.0
		
	return fpr, tpr

	
	

		


# Now compute the IDS performance
def testIDSsystem():

	# Variables
	global ids_training_data
	tpr = []
	fpr = []

	# DO STUFF

	# Setup the plot
	fig, ax = plt.subplots()
	plt.xlim([0, 101])
	plt.ylim([0, 101])
	plt.title('Intrusion Detection System')
	plt.xlabel('False Positive Rate')
	plt.ylabel('Detection Rate')
	plt.grid(linestyle = ':')

	#runs algorithm
	find_total()
	labels = ['Not_f0', 'Not_f1', 'Not_f2', 'Not_f3', 'Not_f4', 'All Features']
	for x in range(0, 6):
		fpr, tpr = algorithm(x)
		plt.plot(np.asarray(fpr), np.asarray(tpr), marker = '.', label=labels[x])
	plt.legend()

	# DO MORE STUFF
	fig.savefig('cmpsc443-ids-output.pdf')

# Main function
def main():
        readIDSData()
        testIDSsystem()

if __name__ == '__main__':
    main()
