#!/usr/bin/env python

# Ryan Wheeler
# This program was created for the final project of cloud computing.
# It uses work queue to parallelize the local solver.
#  condor_submit_workers --cores 2 --memory 100 --disk 1000 fitz80.helios.nd.edu 9098 40
# time python distributeKeys.py practicefile.txt practicefile.txt_output 30

from work_queue import *

import os
import sys

# Main program
if __name__ == '__main__':
	port = 9098

	if len(sys.argv) < 4:
		print "distrbuteKeys <plaintext_file> <ciphertext_file> breakups nthreads"
		print "The files given on the command line should give the plain text and cipher text" # Ask Devonte
		print "Breakups contains how many work_queue tasks to create"
		sys.exit(1)

	tool_path = "solver"
    	# We create the tasks queue using the port 0
	try:	
		q = WorkQueue(port)
    	except:
		print "Instantiation of Work Queue failed!"
        	sys.exit(1)

	print "listening on port %d..." % q.port

    	# We create and dispatch a task for each filename given in the argument list

	infile1 = "%s" % sys.argv[1]
	infile2 = "%s" % sys.argv[2]
	breakups = int(sys.argv[3])
	nthreads = int(sys.argv[4])
	startKey=0; # Best Start Key 282,578,800,148,737 for full keyspace 
	#endkey=1099511627776 # 2^40
	endkey=1073741824# 2^30
	#endkey=32 # 2^5
	#endkey=1024 # 2^10
	#endkey=32768# 2^15
	#endkey=1048576 # 2^20
	iterations=endkey/breakups;
	while startKey<endkey:
		command = './solver %s %s %d %d %d' % (infile1,infile2,startKey, iterations, nthreads)
		t = Task(command)

    		# solver is the same across all tasks, so we can cache it in the * workers.
		t.specify_file(tool_path, tool_path, WORK_QUEUE_INPUT, cache=True)
    		t.specify_file(infile1,infile1,WORK_QUEUE_INPUT,cache=True)
		t.specify_file(infile2,infile2,WORK_QUEUE_INPUT,cache=True)			
		t.specify_cores(nthreads) # Needs Cores Equal to the Number of Threads
		t.specify_memory(100) # Needs 100 MB
		t.specify_disk(1000) # Needs GB
    		# Once all files has been specified, we are ready to submit the task to the queue.
		#t.specify_file("a.$OS.$ARCH","a",WORK_QUEUE_INPUT,cache=True)
		taskid = q.submit(t)
		startKey=startKey+iterations;
		print "submitted task"

	print "waiting for tasks to complete..."
	final=[]
	counter=0
	while not q.empty():
		t = q.wait(5)
		if t:
			print "task complete (return code %d)" % (t.return_status)
			counter=counter+1
			print t.output
			add = t.output.rsplit(",",4)
			if add[0]=="1":
				#q.shutdown_workers(0)
				print add[1]
				print add[2]
				print add[3]
				print counter
				#break;	
	#task object will be garbage collected by Python automatically when it goes out of scope

	#work queue object will be garbage collected by Python automatically when it goes out of scope
	sys.exit(0)
