1 What is runqlen?
Summarize scheduler run queue length as a histogram.


2 Usage of runqlen
USAGE: runqlen [--help] [-C] [-O] [-T] [-f FREQUENCY] [interval] [count]

EXAMPLES:
    runqlen         # summarize run queue length as a histogram
    runqlen 1 10    # print 1 second summaries, 10 times
    runqlen -T 1    # 1s summaries and timestamps
    runqlen -O      # report run queue occupancy
    runqlen -C      # show each CPU separately
    runqlen -f 199  # sample at 199HZ

  -C, --cpus                 Print output for each CPU separately
  -f, --frequency=FREQUENCY  Sample with a certain frequency
  -O, --runqocc              Report run queue occupancy
  -T, --timestamp            Include timestamp on output
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

3 Example
3.1 perf the run queue occupancy 2 times every 5 seconds
sudo sysak runqlen 5 2 -C -T -O

16:06:54
runqocc, CPU 0     0.00%,  AVGlen 0
runqocc, CPU 1     0.00%,  AVGlen 0
runqocc, CPU 2     0.00%,  AVGlen 0
runqocc, CPU 3     0.00%,  AVGlen 0

16:06:55
runqocc, CPU 0     0.00%,  AVGlen 0
runqocc, CPU 1     0.00%,  AVGlen 0
runqocc, CPU 2     0.00%,  AVGlen 0
runqocc, CPU 3     0.00%,  AVGlen 0

3.2 perf the run queue histogram 1 times every 5 seconds
sudo sysak runqlen 5 2 -C -T -O
16:34:56
cpu = 0
     runqlen       : count     distribution
        0          : 495      |****************************************|
cpu = 1
     runqlen       : count     distribution
        0          : 495      |****************************************|
cpu = 2
     runqlen       : count     distribution
        0          : 495      |****************************************|
cpu = 3
     runqlen       : count     distribution
        0          : 495      |****************************************|
