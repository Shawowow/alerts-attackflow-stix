# Robust Cyber Threat Intelligence
This repository implemented a web server that listens for incoming wazuh alerts and output stix object based on the correlation rules.

## Server API Preview
![API Preview](doc/resilmesh_RCTI_webserver.jpg)
## DB Setup
1. Launch mongodb docker:
```bash
docker run -d \
  --name mongodb \
  --restart unless-stopped \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=$MONGODB_USERNAME \
  -e MONGO_INITDB_ROOT_PASSWORD=$MONGODB_PASSWORD \
  -e MONGO_INITDB_DATABASE=yourdatabase \
  -v mongodb_data:/data/db \
  -v mongodb_config:/data/configdb \
  mongodb/mongodb-community-server:latest

  # Directly access mongodb container:
docker exec -it mongodb mongosh mongodb://$MONGODB_USERNAME:$MONGODB_PASSWORD@localhost:27017
  ```

## Correlation Rules structure
Correlation rule will be validated to match STIX version to 2.1 before it can be inserted to the database. Structure of the correlation ruls is as follows:
```json
{
    'name': 'RULE_NAME',
    'techniques': ['Technique_ID1', 'Technique_ID2'],
    'stix_pattern': "[stix2-patterns]"
}
```
Sample correlation rule:
```json
{
    "name": "Valid Accounts Usage Detection",
    "techniques": ["T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004"],
    "stix_pattern": "[process:command_line MATCHES '(?i).*runas.*']"
}
```

## Deploy attackflow container 
```bash
$ docker pull ghcr.io/center-for-threat-informed-defense/attack-flow:main
$ docker run -d --rm --name AttackFlowBuilder -p8000:80 \
   ghcr.io/center-for-threat-informed-defense/attack-flow:main
```

**NOTE**: 
1. Attackflow upload endpoint only support validated attackflow json file (published from Attackflow Builder)
2. It requires every action point within the attackflow satisfy some conditions before it goes to next action. Which means every action node must point to a condition node. This requirement should be checked within the code.