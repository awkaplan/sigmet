# Sigmet

## Description

Sigmet is a small Docker image that updates F5 load-balancer pools according to events from the Marathon Event Stream.  In essence, it provides bare-metal service discovery.

## Docker Image

[awkaplan/sigmet:latest](https://hub.docker.com/r/awkaplan/sigmet/)

## Example

In the screenshots below, you can see that Sigmet has configured pools and members for each Marathon application.

![Marathon](https://raw.githubusercontent.com/awkaplan/sigmet/master/images/marathon.png)

![Pools](https://raw.githubusercontent.com/awkaplan/sigmet/master/images/pools.png)

![Members](https://raw.githubusercontent.com/awkaplan/sigmet/master/images/members.png)

## Configuration

```
usage: sigmet.py [-h] -m MARATHON -b BHOST -u USER -p PASSWORD
                 [--partition PARTITION] [--prefix PREFIX] [--insecure]
                 [--role_user ROLE_USER] [--role_cert ROLE_CERT]
                 [--dcos_master DCOS_MASTER]

optional arguments:
  -h, --help            show this help message and exit
  -m MARATHON, --marathon MARATHON
                        Path to Marathon
  -b BHOST, --bhost BHOST
                        F5 Host
  -u USER, --user USER  F5 Management User
  -p PASSWORD, --password PASSWORD
                        F5 Management Password
  --partition PARTITION
                        Administrative Partition
  --prefix PREFIX       Pool Name Prefix
  --insecure            Verify SSL Certificates
  --role_user ROLE_USER
                        DC/OS Role Account
  --role_cert ROLE_CERT
                        DC/OS Role Certificate
  --dcos_master DCOS_MASTER
                        DC/OS Master
```

### DC/OS (permissive/strict security)

Sigmet requires a service account with the following permissions:
-dcos:adminrouter:service:marathon full
-dcos:service:marathon:marathon:admin:events read
-dcos:service:marathon:marathon:services:/ read

In addition, the `--role_cert` flag must be set to the contents of the service account's private key, `--role_user` to the role account username, and `--dcos_master` set to a master (or master.mesos).

For example:

```
dcos security org service-accounts keypair sigmet-private-key.pem sigmet-public-key.pem
dcos security org service-accounts create -p sigmet-public-key.pem -d "Sigmet service account" sigmet-principal
dcos security org service-accounts show sigmet-principal
dcos security secrets create-sa-secret sigmet-private-key.pem sigmet-principal sigmet-secret
curl -X PUT --cacert dcos-ca.crt -H "Authorization: token=$(dcos config show core.dcos_acs_token)" $(dcos config show core.dcos_url)/acs/api/v1/acls/dcos:service:marathon:marathon:services:%252F -d '{"description":"Allows access to any service launched by the native Marathon instance"}' -H 'Content-Type: application/json'
curl -X PUT --cacert dcos-ca.crt -H "Authorization: token=$(dcos config show core.dcos_acs_token)" $(dcos config show core.dcos_url)/acs/api/v1/acls/dcos:service:marathon:marathon:admin:events -d '{"description":"Allows access to Marathon events"}' -H 'Content-Type: application/json'
curl -X PUT --cacert dcos-ca.crt -H "Authorization: token=$(dcos config show core.dcos_acs_token)" $(dcos config show core.dcos_url)/acs/api/v1/acls/dcos:adminrouter:service:marathon -d '{"description":"Allows full access to Marathon"}' -H 'Content-Type: application/json'
curl -X PUT --cacert dcos-ca.crt -H "Authorization: token=$(dcos config show core.dcos_acs_token)" $(dcos config show core.dcos_url)/acs/api/v1/acls/dcos:service:marathon:marathon:services:%252F/users/sigmet-principal/read
curl -X PUT --cacert dcos-ca.crt -H "Authorization: token=$(dcos config show core.dcos_acs_token)" $(dcos config show core.dcos_url)/acs/api/v1/acls/dcos:service:marathon:marathon:admin:events/users/sigmet-principal/read
curl -X PUT --cacert dcos-ca.crt -H "Authorization: token=$(dcos config show core.dcos_acs_token)" $(dcos config show core.dcos_url)/acs/api/v1/acls/dcos:adminrouter:service:marathon/users/sigmet-principal/full
```

## Notes

Sigmet is built for testing purposes only and is _not_ intended for production environments.

## Definition

> SIGMET, or Significant Meteorological Information, is a weather advisory that contains meteorological information concerning the safety of all aircraft. There are two types of SIGMETs - convective and non-convective. ... SIGMETs are issued as needed, and are valid up to four hours.

[Wikipedia - SIGMET](https://en.wikipedia.org/wiki/SIGMET)
