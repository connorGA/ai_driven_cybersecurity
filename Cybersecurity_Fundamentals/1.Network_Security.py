# 1. Network Security Overview ******************************************************************************************************************************************************************************************
    # Goal: Understand the fundamentals of protecting a network and its data from unauthorized access, misuse, or theft

    # Key Concepts:
        #  CIA Triad: The core objectives of security - Confidentiality, Integrity, and Availability - which define the goals for network security
        #  Network Security Layers: Network security operates on multiple layers(physical, data link, network, transport, and application layers), and protections can applied at each layer 
        
# 2. Firewalls ******************************************************************************************************************************************************************************************
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

# 3. Virtual Private Networks (VPNs) ******************************************************************************************************************************************************************************************
    # VPNs are used to securely connect remote users to a private network over the internet by encrypting the data transmitted between them
    # Key Points:
        # How VPNs work:
            # Tunneling Protocols: PPTP, L2TP, IPsec, SSL/TLS
            # VPN Encryption: Ensures data confidentiality and security when transmitted over public networks
        # Types of VPNs:
            # Remote Access VPN: Allows individual users to connect to a private network from a remote location
            # Site-to-Site VPN: Connects two or more networks together over the internet

    # Introduction to VPNs:
        # A VPN works by routing a devices internet connection through a private service rather than the users regular internet service provider(ISP)
        # The VPN acts as an intermediary between the user getting online and connecting to the internet by hiding their IP address 
    # VPN Protocols:
        # VPN protocols are a combination fo encryption and transmission standards to determine how a users data is transported between their device and the VPN server
        
        #1. PPTP(Point-to-Point Tunneling Protocol):
            # One of the oldest VPN protocols, developed by Microsoft
            # Uses a TCP connection for tunnel management and a GRE protocol for encapsulation
            # PPTP is considered insecure and should be avoided
        #2. L2TP(Layer 2 Tunneling Protocol):
            # Developed by Cisco and Microsoft
            # Combines the best features of PPTP and L2F(Layer 2 Forwarding)
            # Uses UDP for tunnel management and IPsec for encryption
            # It strengthens the data tunnel provided by PPTP but does not provide users with encryption or priavcy capabilities
        #3. (SSTP)Secure Socket Tunneling Protocol:
            # Developed by Microsoft
            # Uses SSL/TLS for encryption
            # SSTP is considered secure and is a good choice for users in countries with strict censorship
            # It transports PPP traffic through the secure sockets layer/transport layer security (SSL/TLS) channel, which provides encryption, key negotiation, and traffic integrity checking.
            # As such, only the two parties that transmit the data are able to decode it.
        #4. IKEv2(Internet Key Exchange version 2):
            # Developed by Microsoft and Cisco
            # Uses IPsec for encryption
            # IKEv2 is considered secure and is a good choice for mobile users
            # It is a tunneling protocol that uses IPsec for encryption, which is a secure network protocol suite that authenticates and encrypts the packets of data sent over an internet protocol network.
        #5. OpenVPN:
            # widely considered the best open-source VPN technology available
            # The software uses pre-shared certificates, secret keys, and usernames and passwords to authenticate every device or server
            # It uses the open secure sockets layer encryption library and TLS, in addition to a custom protocol utilizing SSL/TLS for a key exchange.

#4. Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) ******************************************************************************************************************************************************************************************
    # IDS AND IPS are network security technologies that monitor network traffic for suspicious activity 
    # Key Points:
        # Intrusion Detection System(IDS): Monitors and alerts on suspicious traffic but doesn't block the traffic
        # Intrusion Prevention System(IPS): Actively blocks or rejects malicious traffic based on security rules
        # Types of IDS and IPS:
            # Network-based IDS(NIDS): Monitors network traffic for suspicious activity
            # Host-based IDS(HIDS): Monitors activity on individual devices for suspicious activity
            # Signature-based Detection: Compares traffic to known attack signatures
            # Anomaly-based Detection: Monitors traffic for deviations from normal behavior
            # Inline and Passive Systems: Inline systems actively block traffic, while passive systems only monitor and alert
    
    # IDS vs IPS: Definitions, Comparisons, and Why You Need Both:
        # An intrusion detection system (IDS) monitors traffic on your network, analyzes that traffic for signatures matching know attacks, and when something suspicious happens, you're alerted. In the meantime, traffic keeps flowing.
        # An intrusion prevention system (IPS) also monitors traffic. But when something unusual happens, the traffic stops altogether until you investigate and decide to open the floodgates again.
        # Both systems can: 
            # Monitor. After setup, these programs can look over traffic within parameters you set, and they will work until you turn them off
            # Alert. Both programs will send a notification to those you specify when a problem has been spotted
            # Learn. Both can use machine learning to understand patterns and emerging threats
            # Log. Both will keep records of attacks and responses, so you can adjust your protections accordingly
        # Differences:
            # Response. An IDS is passive, while an IPS is an active control system. You must take action after an IDS alerts you, as your system is still under attack
            # Protection. Arguably, an IDS offers less help when you're under threat. You must figure out what to do, when to do it, and how to clean up the mess. An IPS does all of this for you.
            # False positives. If an IDS gives you an alert about something that isn't troublesome at all, you're the only one inconvenienved. If an IPS shuts down traffic, many people are impacted
            # Cost. An IPS is more expensive than an IDS, as it does more work and offers more protection
        #IDS & IPS Working Together:
            # Many companies avoid the IDS vs. IPS problem by deploying both solutions to protect their assets and servers

#5. Network Segmentation ******************************************************************************************************************************************************************************************
    # Network Segmentation divides a network into smaller parts to control traffic flow and improve security
    # Key Points:
        # Segmentation Methods:
            # Physical Segmentation: Using physical devices like routers and switches to create separate networkls
            # Virtual LANs (VLANs): Logical segmentation within the same physical network 
            # Micro-Segmentation: Using software-defined networking (SDN) to isolate workload

    # Network Segmentation vs microsegmentation:
        # Microsegmentation takes a more granular approach to segmenting networks through virtual local-area networks(VLANs) and access control lists.
        # Microsegmentation builds smaller, more secure zones on a network, enabling the organization to create policies that minimize flows between workloads
    # Network Segmentation vs Internal segmentation:
        # Traditionally, network segmentation was relatively simple, with organizations using static IP addresses and ingress and egress ports that made the process easy to define.
        # However, with the growth of distributed networks and multi-cloud environments, IP addresses are constantly changing.
        # Internal segmentation enables organizations to segment their network and infrastructure assests regardless of their location and whether they are on-premises or on multiple cloud environments. 
    # Network Segmentation vs intent-based segmentation:
        # Intent-based segmentation is a more advanced form of network segmentation that uses automation and orchestration to enforce policies across the network.
        # Intent-based segmentation enables organizations to define policies based on the intent of the network, rather than the technical details of the network itself.
        # Intent-based segmentation enables them to detect and mitigate advanced threats and grant variable access on a need-to-know basis 
        # intenr-based segmentation covers an entire network and its assets, including all endpoints and devices  
    # Network Segmentation vs Zero Trust:
        # Zero Trust is a security model that assumes all users, devices, and applications are untrusted and must be verified before being granted access to the network.
        # Zero Trust is a more comprehensive approach to network security than network segmentation, as it requires organizations to verify all users and devices before granting access to the network.
        # Zero Trust also requires organizations to continuously monitor and analyze network traffic to detect and respond to potential threats in real time.
        # Network segmentation is a key component of Zero Trust, as it enables organizations to create secure zones within the network that can be isolated from other parts of the network.
    
    # Benefits of Network Segmentation:
        # Security: improves security by preventing attacks from spreading across a network and infiltrating unprotected devices.
        # Performance: reduces the congestion that often results in performance drop off 
        # Monitoring and response: makes it easier to monitor and respond to security incidents by isolating affected devices and networks

    # Types of Network Segmentation:
        # Physical Segmentation: Uses physical devices like routers and switches to create separate networks
        # Virtual LANs(VLANs): Logical segmentation within the same physical network
        # Micro-Segmentation: Uses software-defined networking(SDN) to isolate workloads

#6. Network Security Protocols ******************************************************************************************************************************************************************************************
    # Network security protocols are used to secure data transmitted over a network and protect against unauthorized access

    # Key Points:
        # TLS/SSL (Transport Layer Security/Secure Sockets Layer): Encrypts data for secure communication over the internet(e.g, HTTPS)
        # IPsec (Internet Protocol Security): Provides secure communication over IP networks throuhg encryption and authentication
        # SSH(secure shell): Allows Secure remote access to network devices and servers

    # What is SSL/TLS Encryption:
        # SSL/TLS encrypts communications between a client and server, primarily web browsers and web sites/applications
        # SSL(Secure sockets layer) encryption, and its more modern and secure replacement, TLS(Transport layer security) encryption, protect data sent over the internet or a computer network

    # How SSL/TLS Works:
        # SSL/TLS uses a combination of asymmetric and symmetric encryption to secure data transmitted over a network
            # asymmetric encryption: uses a pair of keys to encrypt and decrypt data, used to establish a secure session between a client and server
            # symmetric encryption: uses a single key to encrypt and decrypt data, used to exchange data within a secured session
        # SSL/TLS Handshake:
            # The client contacts the server using a secure URL (https://)
            # The server sens the client its certificate, which contains the server's public key
            # The client verifies this with a Trusted Root Certification Authority to ensure certificate is legitimate
            # The client and server negotiate the strongest type of encryption that each can support
            # The clients encrypts a session(secret) key with the server's public key, and sends it back to the server
            # The server decrypts the client communication with its private key, and the session is established
            # The session key(symmetric encryption) is now used to encrypt and decrypt data transmitted between the client and server

#7. Common Network Attack Vectors ******************************************************************************************************************************************************************************************
    # Understanding common network attack vectors is essential for protecting your network from security threats
    # Key Points:
        # Common Network Attack Vectors:
            # Phishing: Social engineering attack aimed at stealing credentials or sensitive information
            # DDoS(Distributed Denial of Service): Overwhelming a netwrork or service with traffic to make it unavailable
            # Man-in-the-Middle: Intercepting and altering communication between two parties
            # Ransomware: Encrypting data and demanding a ransom for its release
    