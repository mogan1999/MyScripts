#!/usr/bin/env bash

set -e

V2RAY_DIR="/etc/XrayR"

GREEN='\033[0;32m'
NC='\033[0m'

ROUTE_JSON_URL="https://raw.githubusercontent.com/mogan1999/MyScripts/master/route.json"

echo -e "${GREEN}>>> change directory...${NC}"
cd $V2RAY_DIR

echo -e "${GREEN}>>> downloading route.json files...${NC}"
curl -L -o route.json.new $ROUTE_JSON_URL

echo -e "${GREEN}>>> delete old route.json files...${NC}"
rm -f route.json

mv route.json.new route.json

echo -e "${GREEN}完成啦！${NC}"
