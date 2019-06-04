#!/bin/bash
docker run -p 8080:80 gsb-local-agent -apikey "$(python /root/scripts/gsb_docker/get_google_key.py)"

