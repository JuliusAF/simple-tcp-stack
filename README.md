# Simple tcp stack

Basic tcp stack built on top of the framework provided  by ANP
  
 ## How to build 
 
 ```bash
 cmake . 
 make 
 sudo make install  
 ```
 
 This will build and install the shared library. 
 
 ## Scripts 
 
 * sh-make-tun-dev.sh : make a new TUN/TAP device 
 * sh-disable-ipv6.sh : disable IPv6 support 
 * sh-setup-fwd.sh : setup packet forwarding rules from the TAP device to the outgoing interface. This script takes the NIC name which has connectivity to the outside world.  
 * sh-run-arpserver.sh : compiles a dummy main program that can be used to run the shared library to run the ARP functionality 
 * sh-hack-anp.sh : a wrapper library to preload the libanpnetstack and take over networking calls. 
 
 # Setup 
 After a clean reboot, run following scripts in the order 
  1. Make a TAP/TUN device 
  2. Disable IPv6 
  3. Setup packet forwarding rules
