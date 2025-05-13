## Title

### Lab Details 

- Difficulty: Easy 
- Type: Solaris 

#### Tasks

Q1: Which open TCP port is running the ```finger``` service?
 - nmap 10.10.10.76 -sT -A -T4 <!-- scanning for TCP -->
 
    ```
    PORT    STATE SERVICE VERSION
    79/tcp  open  finger?
    |_finger: No one logged on\x0D
    | fingerprint-strings: 
    |   GenericLines: 
    |     No one logged on
    |   GetRequest: 
    |     Login Name TTY Idle When Where
    |     HTTP/1.0 ???
    |   HTTPOptions: 
    |     Login Name TTY Idle When Where
    |     HTTP/1.0 ???
    |     OPTIONS ???
    |   Help: 
    |     Login Name TTY Idle When Where
    |     HELP ???
    |   RTSPRequest: 
    |     Login Name TTY Idle When Where
    |     OPTIONS ???
    |     RTSP/1.0 ???
    |   SSLSessionReq: 
    |_    Login Name TTY Idle When Where
    ```
 Q2: How many users can be found by enumerating the finger service? Considered as user if shown as pts. 

 


