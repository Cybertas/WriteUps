## Broker

### Lab Details 

- Difficulty: Easy
- Type:ActiveMQ, Linux 

#### Tasks
Q1: Which open TCP port is running the ActiveMQ service?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Broker 10.10.11.243` 
```
61613/tcp open     stomp          syn-ack     Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open     http           syn-ack     Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
61616/tcp open     apachemq       syn-ack     ActiveMQ OpenWire transport 5.15.15
```

Q2: What is the version of the ActiveMQ service running on the box?
- based on the output the version is 5.15.15

Q3: What is the 2023 CVE-ID for a remote code execution vulnerability in the ActiveMQ version running on Broker?
- use searchsploit to find a 2023 CVE for ActiveMQ, however unable to find anything 
- search for online and found 
https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell
https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

Q4: What user is the ActiveMQ service running as on Broker?




#### Resources
https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell
https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

#### Lesson Learned
