# Questions
1. How do we test it? [x]
2. We will be having this installed in every host?[x]
3. Doubt in Counter decode in figure paper.
4. XDP can only capture packets from RX (incoming side). Is that a problem ?

# Check
1. Check all TODOs
2. Check if memory allocated is deallocated
3. Check consistency of hashing (in IITH and our impl)
4. Verify lsqr solver(partially verified)
5. Standard values to be used 
6. Concurrency controls - use two flowsets
7. murmur hash implementations
8. make time to 280ms
9. Test with bridging

# Things done
1. Pureset need not be a set as the flows added will be unique always [x]
2. Change implementation of single decode to perform it until no pure cells exist [x]

# Errors
1. Errors due to empty flowsets being passed down to gsl - add a start delay