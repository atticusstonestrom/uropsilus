# uropsilus
Linux based protocol for tunneling TCP traffic over ICMP


Broad overview:

Uropsilus is a protocol built on top of ICMP that allows TCP messages to be tunneled over ICMP echo requests and replies (the same service used by the ping network utility). To run it, you need a computer to act as client (for instance, your laptop connected to a public Wifi network), and a remote computer with a trusted internet connection to act as proxy. Unfortunately, at present both hosts must be running Linux and you must have root access on both. Uropsilus also offers client-proxy encryption, but at present the protocol uses symmetric encryption, so the two hosts must have agreed on a private key beforehand.

On the client side, the protocol works by intercepting outgoing TCP traffic on the computer's network interface and redirecting it to the local loopback interface, where it can be picked up by the tunnel program. The tunnel program then crafts an ICMP echo request whose payload contains (a) a Uropsilus protocol header (detailed below), and (b) a copy of the TCP packet itself, including its IP header, encrypted with the given private key. It then sends this ICMP echo request to the proxy, and awaits an echo reply. Upon receiving the reply, it strips off the ICMP header, parses the Uropsilus header information, and finally decrypts the TCP payload and returns it on the loopback interface, where it can be picked up by the client's relevant web browser or other application. At no point is there any visible TCP traffic to or from the client, and to the client's network gateway all of the client's traffic just looks like hundreds of ping requests and replies.

On the remote side, the proxy waits for connection requests from clients, and upon receiving one allocates the memory and relevant data structures for the new client. It then listens for ICMP echo requests from the client, and upon receiving one strips off the ICMP header, parses the Uropsilus header information, decrypts the TCP payload, and sends it off to the server it was originally destined for. It has to modify the TCP packet in a few ways, first changing its source address from the client's address to its own, so that it will be the one to receive the TCP responses from the server. Also, because the proxy needs to be able to handle multiple clients, it has to have a way of identifying which client the server's TCP response is destined for, so Uropsilus implements a simple form of Network Address Port Translation (NAPT), changing the source port of the TCP payload and implementing a port translation table that allows it link certain port numbers with their corresponding clients. Upon receiving a TCP response from a server, it checks the NAPT table (discarding the packet if a corresponding port entry is not found), changes the packet's destination port and destination IP address to those of the corresponding client in the NAPT table, encrypts the entire packet and wraps it up in ICMP and Uropsilus headers, sending it as an echo reply to the client upon its next receipt of an echo request.


Why and when to use:


Technical details and challenges:
	Header and fragmentation, expired IDs


Future directions:
