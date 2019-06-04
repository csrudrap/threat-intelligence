# threat-intelligence directory
git clone https://github.com/christiandt/google-safebrowsing-docker.git
sed -i 's/FROM golang:1.6/FROM golang:1.7/g' google-safebrowsing-docker/Dockerfile
source ThreatIntelligence/bin/activate 
apt-get install -y python-pip
pip install -r requirements.txt
apt-get install -y docker.io
cd google-safebrowsing-docker
docker build -t gsb-local-agent .
mkdir -p /root/scripts/gsb_docker/
cd ..
cp gsb_docker.sh /root/scripts/gsb_docker/
cp apikeys.conf /root/scripts/gsb_docker/
cp get_google_key.py /root/scripts/gsb_docker/
cp gsb-docker.service /etc/systemd/system/
cd /etc/systemd/system;sudo systemctl enable gsb-docker.service
cd -
apt-get install -y mongodb mongodb-clients
mkdir /data
mkdir /data/db
systemctl enable mongodb
systemctl start gsb-docker
git update-index --assume-unchanged apikeys.conf
