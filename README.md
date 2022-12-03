Suricata Firewall is a project I made for helping me learn Python by applying what I learned to real world use case. 

This is program is set up to run as a Linux deamon. In practice, it would run on a Linux box on a bridge interface 
monitoring network traffic. The program acts as a firewall by scanning Suricata logs for certain alerts and blocking 
the corresponding IP addresses by adding them to an ipset list. Before running the program, your system needs to 
have ipset installed and an ipset list created. To have your system block the IPs, make sure to add the ipset list 
to iptables.

