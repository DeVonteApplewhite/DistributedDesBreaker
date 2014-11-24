DistributedDesBreaker
=====================

Attempts a brute force attack on a DES encrypted file using distributed computing

Main Components of the project:
-------------------------------

*Local Solver
	1. Takes a starting point and tries multiple keys up to an upper bound
	2. Needs to be as efficient as possible
	3. Makes use of the DES library
*Problem Space
	1. The DES key is 64 bits in the DES encrpytion scheme the solver uses
	2. DES keys are actually 56 bits, but the above scheme uses 8 bits of parity to make
	   the key more resistant to brute-force attacks
	3. Need a way to quickly process only valid keys to limit the amount of redundant
	   key checking 
*Distributed Implementation
	1. Uses WorkQueue with a pool of Condor workers
	2. Idea is to dispatch tasks that cover a portion of the key space to increase the
	   throughput of keys per second processed.
