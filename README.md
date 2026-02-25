*Title*
Sniffer

*Problem Statement:-*
This is a C program that compiles using Makefile and runs on linux (posix).
The program:
1. Use libpcap library to read packets from one of the system network interfaces (for example eth0) or a pcap file.
2. Interface or pcap file has to be provided through command line.
3. For each packet it has to extract:
   - mac addresses of source and destination,
   - IP addresses of source and destination,
   - for TCP and UDP packets source and destination ports.
4. If a packet is part of the HTTP stream it has to find GET, POST requests and extract:
   - Host, and User Agent strings.
5. Extracted data has to be stored in the text file specified as command line argument.
6. Use a multi-threaded approach to solve this problem. The 1st thread reads from the interface and parses the host and user agent, storing the result in a queue. The 2nd thread reads from this queue and writes the results in the text file. (In order for the writing to file mechanism not to slow down the packet reading, and extraction.
7. The program has to follow each new TCP connection and when connection is terminated it has to print the total number of packets transferred IN and OUT as well as duration of the connection in milliseconds. The data structure used for tracking connections should be designed for high speed processing, so not a normal array.

*Build*
make clean; make

*Run*
./sniffer -i eno1 -o output.txt
or
./sniffer -r sample.pcap -o output.txt

*Notes*
1. Works only for HTTP (not HTTPS)
2. IPv4 only (not IPV6)
3. Uses a hash table for fast TCP connection tracking instead of Normal Array.