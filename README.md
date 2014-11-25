DistributedDesBreaker
=====================

Attempts a brute force attack on a DES encrypted file using distributed computing

Main Components of the project:
-------------------------------

* Local Solver
  - Takes a starting point and tries multiple keys up to an upper bound
  - Needs to be as efficient as possible
  - Makes use of the DES library
* Problem Space
  - The DES key is 64 bits in the DES encrpytion scheme the solver uses
  - DES keys are actually 56 bits, but the above scheme uses 8 bits of parity to make
    the key more resistant to brute-force attacks
  - Need a way to quickly process only valid keys to limit the amount of redundant
    key checking 
* Distributed Implementation
  - Uses WorkQueue with a pool of Condor workers
  - Idea is to dispatch tasks that cover a portion of the key space to increase the
     throughput of keys per second processed.
  - Tasks will be submitted in the form "./solver <plainblock> <cipherblock>
    <starting key> <number of iterations>".
    * <plainblock> is an 8-byte argument on the command line that corresponds
      to the chunk of plaintext being processed.
    * <cipherblock> is an 8-byte argument on the command line that corresponds
      to the plaintext chunk that has been encrypted and is being processed.
    * <starting key> is the starting value to check for the key at.
    * <number of iterations> is the number of subsequent keys to process
      starting at <starting key>.
