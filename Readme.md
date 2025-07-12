TCP Hijacking
====

Ousema BOUANENI

Done as part of a cybersecurity course at École polytechnique (CSC_43M05_EP)

# Program description
`tcp_hijack` is a command line utility that launches a telnet Man-in-the-middle attack on a network interface of the user's choice.

Once you're in the root directory of the project, it can be compiled with a simple:
```console
$make
```

The usage syntax is the following:
```console
#./tcp_hijack
```

# Setup description
## The network
In order to demonstrate the attack, I have set up 3 different VMs running Ubuntu Server 24.04: an attacker (machine1), a telnet client (machine2) and a telnet server (machine3). All three machines are connected to the same network inet1 using a hub, as is illustrated by the following diagram:
```
               IP: 172.16.0.1                 
            ┌────────────────────┐             
            │ machine1 (attacker)│             
            └─────────┬──────────┘             
                      │inet1                 
                      │                        
                  ┌───┴────┐                   
        ┌─────────┤  Hub   ├──────────┐         
        │inet1    └────────┘ inet1    │         
        │                             │         
┌───────┴───────────┐        ┌────────┴──────────┐
│ machine2 (client) │        │ machine3 (server) │
└───────────────────┘        └───────────────────┘
   IP: 172.16.0.2                IP: 172.16.0.3  
```

The DNS server has been set up on machine3 using `telnetd`.
```console
#sudo apt update && sudo apt install telnetd
#echo 'telnet  stream  tcp     nowait  root    /usr/sbin/tcpd  /usr/sbin/telnetd' >> /etc/inetd.conf
#systemctl restart inetd
```

## The attack
After getting the `tcp_hijack` executable program into machine1 (for instance using `scp`), the effects of the attack can be illustrated by running `tcp_hijack` on the attacker over the inet1 network interface and making machine2 launch a telnet connection to machine3. The connection should be reset for machine2 once the authentification step has ended and a `hack.txt` file should appear in machine3 as can be seen in the attached `demonstration.mp4` file.