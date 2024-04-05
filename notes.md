# Questions
1. How do we test it? [x]
2. We will be having this installed in every host?
3. Doubt in Counter decode in figure paper.

4. XDP can only capture packets from RX (incoming side). Is that a problem ?

# Check
1. Check all TODOs
2. Check if memory allocated is deallocated
3. Check consistency of hashing
4. Verify lsqr solver(partially verified)

# Things done
1. Pureset need not be a set as the flows added will be unique always [x]
2. Change implementation of single decode to perform it until no pure cells exist [x]