# threat-intelligence
Framework to identify malicious URLs

This is a framework to collect feeds from various sources that provide malicious URL feeds. 
This framework starts with a main thread and creates one thread per feed that would run forever to execute worker code for each feed. A signal handler for SIGINT helps in killing all threads with a Ctrl-C.

Steps to setup this framework:

First, apikeys.conf should be populated with entries that follow the pattern "Google:XXXXXXXX".
Capitalize the first letter and add new API keys on different lines.
The script setup.sh also excludes "*.conf" to git so that changes on these configuration files are not tracked.

Run as:
    sudo sh setup.sh
This will execute the steps below.


1. git clone https://github.ncsu.edu/csrudrap/threat-intelligence.git
   
   This will create a threat-intelligence directory with an empty google-safebrowsing-docker directory. 

2. cd threat-intelligence
   git clone https://github.com/christiandt/google-safebrowsing-docker.git
   
   After cloning the google-safebrowsing-docker submodule, change the Go version to 1.7 in the Dockerfile.
   cd into the threat-intelligence directory and do a git add .
   This will add the Dockerfile changes. Commit and push.

   The Docker part is ready to run.

3. source ThreatIntelligence/bin/activate 

   where ThreatIntelligence is in the directory threat-intelligence. It is the virtual environment.

4. sudo apt-get install python-pip
   sudo pip install -r requirements.txt

   This will install the necessary python packages
   
5. sudo apt-get install docker.io
   cd google-safebrowsing-docker
   sudo docker build -t gsb-local-agent .
   sudo docker run -p 8080:80 gsb-local-agent -apikey AIzaSyAnZ3bSDQwk8kIpCtQi6SKVia_sh6-EsBQ

6. sudo apt-get install mongodb mongodb-clients
   mkdir /data/db/

7. In a new terminal:
   python populate_db.py --gsb-url <GSB_HOST>:8080 --mongod-url <MONGO_HOST>
   For local testing, GSB_HOST and MONGO_HOST are usually 127.0.0.1
