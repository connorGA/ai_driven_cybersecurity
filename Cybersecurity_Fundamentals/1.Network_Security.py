# 1. Network Security Overview
    # Goal: Understand the fundamentals of protecting a network and its data from unauthorized access, misuse, or theft

    # Key Concepts:
        #  CIA Triad: The core objectives of security - Confidentiality, Integrity, and Availability - which define the goals for network security
        #  Network Security Layers: Network security operates on multiple layers(physical, data link, network, transport, and application layers), and protections can applied at each layer 
        
# 2. Firewalls
    # A firewall is a network security device that monitors and controls incoming and outgoing traffic based on predetermined security rules

    # Types of Firewalls:
        # Packet Filtering Firewall: Inspects packets and filters based on IP addresses, ports, and protocols
        # Stateful Inspection Firewall: tracks the state of active connections and makes decisions based on context 
        # Proxy Firewall: Acts as an intermediary for requests from clients seeking resources from other servers
        # Next-Generation Firewall: Combines traditional firewall capabilities with additional features like deep packet inspection, intrusiion prevention, and application awareness
        # Web Application Firewall: Protects web applications from common web-based attacks like SQL injection, cross-site scripting, and cross-site request forgery
        # Host-based Firewall: Software-based firewall that runs on individual devices and monitors traffic to and from that device
        # Network-based Firewall: Hardware-based firewall that protects an entire network from external threats
        # Cloud Firewall: Firewall that protects cloud-based resources and applications

    # Introduction to Firewalls: 
        # The firewall is the barrier between a trsuted and untrusted network, often between your LAN and WAN.
        # Typically placed in the forwarding path so that all packets have to be checked by the firewall before they are allowed to pass

    #1. Stateful Filtering:
        # Firewalls use stateful filtering, meaning they keep track of all incoming and outgoing connections.
        # Example: A computer on the LAN uses its email client to connect to a mail server on the internet. 
        #          The client will start the connection with a TCP three-way handshake, which the firewall sees. 
        #          The firewall will keep track of this connection and when the mail server responds, the firewall will automatically permit this traffic to return to the client. 
    #2. Packet Inspection: 
        # Modern firewalls can inspect packets at the application layer, which allows them to block or allow traffic based on the application that is generating the traffic.
        # Example: A firewall can block all traffic from a web browser that is known to be malicious.
        # Example: Instead of blocking all IP addresses that belong to lolcats.com, you can create a filter that looks for the URI in HTTP requests and block those instead

    #3. Security Zones: 
        # If you have a lot of interfaces and/or access list rules, configuration can become and administrative nightmare
        # To simplify this, you can group interfaces into security zones and apply rules to the zones instead of individual interfaces
        # Our LAN is our trusted network, which would have a high security level. The WAN is untrusted, so it will have a low security level
        # This means traffic from our LAN > WAN will be permitted. Traffic from WAN to our LAN will be denied
        # Most companies will have one or more servers that should be reachable from the internet(eg. mail or web servers).
        # Instead of placing these on the inside, we use a third zone called the DMZ(Demilitarized Zone).
        # The DMZ is a neutral zone between the LAN and WAN. Traffic from the WAN is allowed to reach the DMZ, but not the LAN.

    #4. Conclusion:
        # Firewalls use stateful filtering to keep track of all incoming and outgoing connections
        # They are also able(depending on the firewall) to inspect up to layer 7 of the OSI model, looking into the payload of applications 
        # They also use security zones where traffic from a high security level is permitted to go to a lower security level. 
        # Traffic from a low secuirty level to a higher security level will be denied, exceptions can be made with access lists.