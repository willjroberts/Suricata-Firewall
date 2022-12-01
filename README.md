This is a program meant to act as a firewall on a Linux box by scanning Suricata logs for certain alerts and blocking the corresponding IP addresses.
Before running the program, your system needs to have ipset installed and an ipset list created. To have your system block the IPs, make sure to add
the ipset list to iptables.

