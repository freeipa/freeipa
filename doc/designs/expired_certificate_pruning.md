# Expired Certificate Pruning

## Overview

https://pagure.io/dogtagpki/issue/1750

When using short-lived certs and regular issuance, the expired certs can build up in the PKI database and cause issues with replication, performance and overall database size.

PKI has provided a new feature in 11.3.0, pruning, which is a job that can be executed on a schedule or manually to remove expired certificates and requests.

Random Serial Numbers v3 (RSNv3) is mandatory to enable pruning.

Both pruning and RSNv3 require PKI 11.3.0 or higher.

## Use Cases

ACME certificates in particular are generally short-lived and expired certificates can build up quickly in a dynamic environment. An example is a CI system that requests one or more certificates per run. These will build up infinitely without a way to remove the expired certificates.

Another case is simply a very long-lived installation. Over time as hosts come and go certificates build up.

## How to Use

https://github.com/dogtagpki/pki/wiki/Configuring-CA-Database-Pruning provides a thorough description of the capabilities of the pruning job.

The default configuration is to remove expired certificates and incomplete requests after 30 days.

Pruning is disabled by default.

Configuration is a four-step process:

1. Configure the expiration thresholds
2. Enable the job
3. Schedule the job
4. Restart the CA

The job will be scheduled to use the PKI built-in cron-like timer. It is configured nearly identically to `crontab(5)`. On execution it will remove certificates and requests that fall outside the configured thresholds. LDAP search/time limits can be used to control how many are removed at once.

In addition to the automated schedule it is possible to manually run the pruning job.

The tool will not restart the CA. It will be left as an exercise for the user, who will be notified as needed.

### Where to use

The pruning configuration is not replicated. It should not be necessary to enable this task on all IPA servers, or more than one.

Running the task simultaneously on multiple servers has a few downsides:

* Additional stress on the LDAP server searching for expired certificates and requests
* Unnecessary replication load deleting the same entries on multiple servers

While enabling this on a single server represents a single-point-of-failure there should be no catastrophic consequences other than expired certificates and requests potentially building up. This can be cleared by enabling pruning on a different server. Depending on the size of the backlog this could take a couple of executions to catch up.

## Design

There are several operations, most of which act locally and one of which uses the PKI REST API.

1. Updating the job configuration (enable, thresholds, etc). This will be done by running the `pki-server ca-config-set` command which modifies CS.cfg directly per the PKI wiki. A restart is required.

2. Retrieving the current configuration for display. The `pki-server ca-config-find` command returns the entire configuration so the results will need to be filtered.

3. Managing the job. This can be done using the REST API, https://github.com/dogtagpki/pki/wiki/PKI-REST-API . Operations include enabling the job and triggering it to run now.

Theoretically for operations 1 and 2 we could use existing code to manually update `CS.cfg` and retrieve values. For future-proofing purposes calling `pki-server` is probably the better long-term option given the limited number of times this will be used. Configuration is likely to be one and done.

There are four values each that can be managed for pruning certificates and requests:

* expired cert/incomplete request time
* time unit
* LDAP search size limit
* LDAP search time limit (in seconds)

The first two configure when an expired certificate or incomplete request will be deleted. The unit can be one of: minute, hour, day, year. By default it is 30 days.

The LDAP limits control how many entries are returned and how long the search can take. By default it is 1000 entries and unlimited time (0 == unlimited, unit is seconds).

### Configuration settings

The configuration values will be set by running `pki-server ca-config-set` This will ensure best forward compatibility. The options are case-sensitive and not validated by the CA until restart. The values are not applied until the CA is restarted.

### Configuring job execution time

The CA provides a cron-like interface for scheduling jobs. To configure the job to run at midnight on the first of every month the PKI equivalent command-line is:

```
pki-server ca-config-set jobsScheduler.job.pruning.cron `"0 0 1 * *"`
```

This will be the default when pruning is enabled. A separate configuration option will be available for fine-tuning execution time.

The format is defined https://access.redhat.com/documentation/en-us/red_hat_certificate_system/9/html/administration_guide/setting_up_specific_jobs#Frequency_Settings_for_Automated_Jobs

### REST Authentication and Authorization

The REST API for pruning is documented at https://github.com/dogtagpki/pki/wiki/PKI-Start-Job-REST-API

A PKI job can define an owner that can manage the job over the REST API. We will automatically define the owner as `ipara` when pruning is enabled.

Manually running the job will be done using the PKI REST API. Authentication to this API for our purposes is done at the `/ca/rest/account/login` endpoint. A cookie is returned which will be used in any subsequent calls. The IPA RA agent certificate will be used for authentication and authorization.

### Commands

This will be implemented in the ipa-acme-manage command. While strictly not completely ACME-related this is the primary driver for pruning.

A new verb will be added, pruning, to be used for enabling and configuring pruning.

### Enabling pruning

`# ipa-acme-manage pruning --enable`

Enabling the job will call

`# pki-server ca-config-set jobsScheduler.job.pruning.enabled true`

This will also set jobsScheduler.job.pruning.cron to `"0 0 1 * *"` if it has not already been set.

Additionally it will set the job owner to `ipara` with:

`# pki-server ca-config-set jobsScheduler.job.pruning.owner ipara`

Disabling the job will call

`# pki-server ca-config-unset jobsScheduler.job.pruning.enabled`

### Cron settings

To modify the cron settings:

`# ipa-acme-manage pruning --cron="Minute Hour Day_of_month Month_of_year Day_of_week"`

Validation of the value will be:
* each of the options is an integer
* minute is within 0-59
* hour is within 0-23
* day of month is within 0-31
* month of year is within 1-12
* day of week is within 0-6

No validation of setting February 31st will be done. That will be left to PKI. Buyer beware.

### Disabling pruning

`# ipa-acme-manage pruning --disable`

This will remove the configuration option for `jobsScheduler.job.pruning.cron` just to be sure it no longer runs.

### Configuration

#### Pruning certificates

`# ipa-acme-manage pruning --certretention=VALUE --certretentionunit=UNIT`

will be the equivalent of:

`# pki-server ca-config-set jobsScheduler.job.pruning.certRetentionTime 30`

`# pki-server ca-config-set jobsScheduler.job.pruning.certRetentionUnit day`

The unit will always be required when modifying the time.

`# ipa-acme-manage pruning --certsearchsizelimit=VALUE --certsearchtimelimit=VALUE`

will be the equivalent of:

`# pki-server ca-config-set jobsScheduler.job.pruning.certSearchSizeLimit 1000`

`# pki-server ca-config-set jobsScheduler.job.pruning.certSearchTimeLimit 0`

A value of 0 for searchtimelimit is unlimited.

#### Pruning requests

`# ipa-acme-manage pruning --requestretention=VALUE --requestretentionunit=UNIT`

will be the equivalent of:

`# pki-server ca-config-set jobsScheduler.job.pruning.requestRetentionTime 30`

`# pki-server ca-config-set jobsScheduler.job.pruning.requestRetentionUnit day`

The unit will always be required when modifying the time.

`# ipa-acme-manage pruning --requestsearchsizelimit=VALUE --requestsearchtimelimit=VALUE`


will be the equivalent of:

`# pki-server ca-config-set jobsScheduler.job.pruning.requestSearchSizeLimit 1000`

`# pki-server ca-config-set jobsScheduler.job.pruning.requestSearchTimeLimit 0`

A value of 0 for searchtimelimit is unlimited.

These options set the client-side limits. The server imposes its own search size and look through limits. This can be tuned for the uid=pkidbuser,ou=people,o=ipaca user via https://access.redhat.com/documentation/en-us/red_hat_directory_server/11/html/administration_guide/ldapsearch-ex-complex-range

### Showing the Configuration

To display the current configuration run `pki-server ca-config-find` and filter the results to only those that contain `jobsScheduler.job.pruning`.

Default values are not included so will need to be set by `ipa-acme-manage` before displaying.

Output may look something like:

```console
# ipa-acme-manage pruning --config-show
Enabled: TRUE
Certificate retention time: 30 days
Certificate search size limit: 1000
Certificate search time limit: 0
Request retention time: 30 days
Request search size limit: 1000
Request search time limit: 0
Cron: 0 0 1 * *
```

### Manual pruning

`# ipa-acme-manage pruning --run`

This is useful for testing the configuration or if the user wants to use the system cron or systemd timers for handling automation.

## Implementation

For online REST operations (login, run job) we will use the `ipaserver/plugins/dogtag.py::RestClient` class to manage the requests. This will take care of the authentication cookie, etc.
The class uses dogtag.https_request() will can take PEM cert and key files as arguments. These will be used for authentication.

For the non-REST operations (configuration, cron settings) the tool will fork out to pki-server ca-config-set.

### UI

This will only be configurable on the command-line.

### CLI

Overview of the CLI commands. Example:


| Command |	Options |
| --- | ----- |
| ipa-acme-manage pruning | --enable |
| ipa-acme-manage pruning | --disable |
| ipa-acme-manage pruning | --cron=`"0 0 1 * *"` |
| ipa-acme-manage pruning | --certretention=30 --certretentionunit=day |
| ipa-acme-manage pruning | --certsearchsizelimit=1000 --certsearchtimelimit=0 |
| ipa-acme-manage pruning | --requestretention=30 --requestretentionunit=day |
| ipa-acme-manage pruning | --requestsearchsizelimit=1000 --requestsearchtimelimit=0 |
| ipa-acme-manage pruning | --config-show |
| ipa-acme-manage pruning | --run |

ipa-acme-manage can only be run as root.

### Configuration

Configuration changes will be made to /etc/pki/pki-tomcat/ca/CS.cfg 

## Upgrade

No expected impact on upgrades.

## Test plan

Testing will consist of:

* Use the default configuration
* enabling the pruning job
* issue one or more certificates
* move time forward +1 days after expiration
* manually running the job
* validating that the certificates are removed

For size/time limit testing, create a large number of certificates/requests and set the search limit to a low value, then ensure that the number of deleted certs is equal to the search limit. Testing timelimit in this way may be less predictable as it may require a massive number of entries to find to timeout on a non-busy server.

## Troubleshooting and debugging

The PKI debug log will contain job information.

```
2022-12-08 21:14:25 [https-jsse-nio-8443-exec-8] INFO: JobService: Starting job pruning
2022-12-08 21:14:25 [https-jsse-nio-8443-exec-8] INFO: JobService: - principal: null
2022-12-08 21:14:51 [https-jsse-nio-8443-exec-10] INFO: JobService: Starting job pruning 2022-12-08 21:14:51 [https-jsse-nio-8443-exec-10] INFO: JobService: - principal: null
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: Authenticating certificate chain:
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: - CN=IPA RA,O=EXAMPLE.TEST
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: - CN=Certificate Authority,O=EXAMPLE.TEST
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: LDAPSession: Retrieving cn=19072098145751813471503860299601579276,ou=certificateRepository, ou=ca,o=ipaca
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: CertUserDBAuthentication: UID ipara authenticated.
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: User ipara authenticated
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: UGSubsystem: Retrieving user uid=ipara,ou=People,o=ipaca
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: User DN: uid=ipara,ou=people,o=ipaca
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: Roles:
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: - Certificate Manager Agents
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: - Registration Manager Agents
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: - Security Domain Administrators
2022-12-08 21:15:11 [https-jsse-nio-8443-exec-11] INFO: PKIRealm: - Enterprise ACME Administrators
2022-12-08 21:15:24 [https-jsse-nio-8443-exec-12] INFO: JobService: Starting job pruning
2022-12-08 21:15:24 [https-jsse-nio-8443-exec-12] INFO: JobService: - principal: GenericPrincipal[ipara(Certificate Manager Agents,Enterprise ACME Administrators,Registration Manager Agents,Security Domain Administrators,)]
2022-12-08 21:15:24 [https-jsse-nio-8443-exec-12] INFO: JobsScheduler: Starting job pruning
2022-12-08 21:15:24 [pruning] INFO: PruningJob: Running pruning job at Thu Dec 08 21:15:24 UTC 2022
2022-12-08 21:15:24 [pruning] INFO: PruningJob: Pruning certs expired before Tue Nov 08 21:15:24 UTC 2022
2022-12-08 21:15:24 [pruning] INFO: PruningJob: - filter: (&(x509Cert.notAfter<=1667942124527)(!(x509Cert.notAfter=1667942124527)))
2022-12-08 21:15:24 [pruning] INFO: LDAPSession: Searching ou=certificateRepository, ou=ca,o=ipaca for (&(notAfter<=20221108211524Z)(!(notAfter=20221108211524Z)))
2022-12-08 21:15:24 [pruning] INFO: PruningJob: Pruning incomplete requests last modified before Tue Nov 08 21:15:24 UTC 2022
2022-12-08 21:15:24 [pruning] INFO: PruningJob: - filter: (&(!(requestState=complete))(requestModifyTime<=1667942124527)(!(requestModifyTime=1667942124527)))
2022-12-08 21:15:24 [pruning] INFO: LDAPSession: Searching ou=ca, ou=requests,o=ipaca for (&(!(requestState=complete))(dateOfModify<=20221108211524Z)(!(dateOfModify=20221108211524Z)))
```

### Manual execution fails with Forbidden

If manually running pruning fails with a message like:

```console
# ipa-acme-manage pruning --run
CalledProcessError(Command ['pki', '-C', '/tmp/tmppyyd3hfq/pwdfile.txt', '-d', '/tmp/tmppyyd3hfq', '-n', 'CN=IPA RA,O=EXAMPLE.TEST', 'ca-job-start', 'pruning'] returned non-zero exit status 255: 'PKIException: Forbidden\n')
The ipa-acme-manage command failed.
```

You probably forgot to restart the CA after enabling pruning.
