# pslmap-rs

pslmap (nmap rust version based on [pistol-rs](https://github.com/rikonaka/pistol-rs)).

One of my design philosophies for this software is to let users know what each command is doing. I personally have great respect for nmap's status in the scanner industry, but there are some problems with the software's design logic.

A very simple example is the `-sn` option of nmap. The meaning of this option is to perform a `ping scan` on the target IP address, but in actual execution, when the target address is local, it actually performs an `arp scan`. If the user does not read the nmap documentation or code carefully, he will be confused as to why there is no ICMP packet sending record when performing host discovery on the local IP address.

So when I revisited nmap and redesigned its rust version `pslmap`, I hoped that when the user executed a `ping scan`, it would definitely be a `ping scan`. This also has its drawbacks, that is, it does not provide some very simple but very powerful commands to some beginners like nmap does. Instead, it provides very specific and accurate commands.