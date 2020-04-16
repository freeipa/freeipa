# Expiring Password Notifications

**DESIGN STAGE**

## Overview

A method to warn users via email that their IPA account password is about to expire.
Ticket [link](https://pagure.io/freeipa/issue/3687).

## User Stories

[0] As an IPA user, I want to be notified by email and through the WebUI when my password is near its expiry date so that I change my password before it expires.

Outcome: Users whose passwords are expiring receive an email.
NB: The WebUI warning [already exists](https://github.com/freeipa/freeipa/pull/4561). Document (ipapwdexpadvnotify) usage.

[1] As an IPA administrator, I want to be able to provide a template for the above emails so that they conform to company policy.

Outcome: IPA administrators can edit an email template that is used for notifications.

[2] As an IPA administrator, I want to be able to set a list of days before password expiry date on which these notifications are sent so that users are warned well in advance and often enough to change their passwords so that our IT does not get asked about it.

Outcome: Users receive notifications on an IPA-admin-specified list of days before their password expires.
Supersedes [1].

[3] As an IPA administrator, I want to be able to set smtp client parameters so that the notification emails are sent properly.

Outcome: Emails are sent according to the SMTP parameters set in the configuration file.

[4] As an IPA administrator, I do not want to notify users whose accounts are disabled because it makes no sense to.

Outcome: If an account is disabled (using [nsaccountlock](https://directory.fedoraproject.org/docs/389ds/howto/howto-account-inactivation.html)), no emails are sent when the password is near expiry.

[5] As an IPA administrator, I want to specify a maximum number of emails to be sent daily to make sure my SMTP server is not flooded by the notification engine.

Outcome: When more emails than what the max_emails_per_day setting is set at would be sent, send a warning to the admin email and then send only max_emails_per_day emails.

[6] As an IPA administrator, I want the tool to be packaged using standard system tools (RPM) and its configuration files/templates flagged as such so that I can deploy/configure/activate it easily.

Outcome: Installing an RPM, configuring the tool and activating a systemd timer is enough to have the tool run every night.

[7] As an IPA administrator, I want existing deployment tools (ansible-freeipa) for IPA to be able to deploy the notification tool on whichever IPA system I choose to have a consistent experience.

Outcome: Ansible-freeipa contains a role that deploys and configures the tool.

[8] As an IPA administrator, I want to be able to configure the notification tool in dry-run mode to know how many emails would be sent or to hook external tooling.

Outcome: If dry-run is specified or configured, no emails are sent but a JSON report is produced instead.

[9] As an IPA administrator, I want the tool to ship in its dry-run mode by default to avoid sending thousands of notifications on first run.

Outcome: Dry-run is the default in the configuration.

[10] As an IPA administrator, I want to be able to generate a list of users whose passwords are near expiry date for tracking purposes.

Outcome / Notes: Matches [8]

[11] As an IPA administrator, I want the tool to stop running and display a warning message if the MTA refuses the connection or the authentication.

Outcome: The tool errors out on MTA connection refused or authentication refused errors.


## Logic

The algorithm can be reduced to:
* List IPA users for which:
  * Account is not disabled / locked
  * krbPasswordExpiration is in less than x days in the future and more than y days in the future, x and y determined from the configuration file. Fetch their uid, krbPasswordExpiration, mail and cn attributes in the process:

```shell
$ ldapsearch -LLL -Y GSSAPI -b "cn=users,cn=accounts,$BASEDN" '(&(!(nsaccountlock=TRUE))(krbPasswordExpiration<=max_date)(krbPasswordExpiration>=min_date))' uid krbPasswordExpiration mail cn
```

* Sort by urgency
* If dry-run was not specified, send email to all values of the "mail" (or user-specified) attribute, stopping at max_emails_per_day and if necessary warn the administrator.
* Otherwise, output json


## Possible approaches

### Approach 1

IPA ships a standalone tool launched by a systemd timer.

This tool does not impact IPA in any way:
* it is self-contained (does not need a new plugin).
* it could be extended to maintain its own state (if more than max_emails_per_day mails would be sent, store in a local DB the ones that should be sent the next day).
* it can be deployed on multiple runners to:
  * have multiple notification date ranges (e.g. 7 days, 14 days) executed in different places
  * contact different SMTP servers in different places of a stretched cluster

The tool could be enhanced and tested on IPA clients too. 

The tool consists roughly in two distinct parts:
* a class that generates uid/krbpasswordexpiration/mail dictionaries based on a LDAP query.
* a class that sends notifications. It connects to a SMTP server using the provided credentials, takes a list of uid/krbpasswordexpiration/mail dictionaries as input, and sends notifications using the provided template. This class must report any issues (SMTP errors, etc) and the number/list of emails that were sent.

* Knobs
  * ```--dry-run```

* Configuration File items
  * A list of days before expiry date on which to send notifications: 15,7,2 for instance
  * User attribute to use for email addresses (default: mail)
  * Mode: enabled / dry-run
  * Max-emails: integer, max emails to send per run (no state is kept).
  * Admin email to use when problems arise esp. over max-emails.
  * Charset: UTF-8 by default. Not sure if it is wise to make it configurable yet.
  * SMTP server
  * SMTP port
  * SMTP user
  * SMTP password

* Email template (separate file in Jinja2 format):
  From:
  Subject:
  Body, including template variables: IPA domain, uid and krbPasswordExpiration

* Deployment
  As part of a subpackage of IPA. The proposed RPM does not depend on IPA server bits and could even be deployed in a client. 

The subpackage would deploy the tool & its configuration file & its systemd timer.
It would own the output directory if there is one (not sure yet).
This subpackage would be deployed, configured and the timer enabled by an Ansible role.


#### Usage

Listing affected users:
```
# ipa-epn --dry-run
```
Output:
```json
[
    {
        "uid": "user3",
        "cn": "user 3",
        "date": "2020-04-21 00:00:08",
        "mail": "['user3@laptop.example.org']"
    },
    {
        "uid": "user5",
        "cn": "user 5",
        "date": "2020-04-17 15:51:53",
        "mail": "['user5@laptop.example.org']"
    }
]
```

Sending notifications:
```
# ipa-epn
```


### Approach 2

IPA is extended so that an IPA command is able to list the users whose password expirations are within a specified range.
The output must be json to be easily consumable by external tooling.

IPA also ships a new tool leveraging the IPA plugin. The tool usage is similar to Approach #1, but the internal architecture is different.
Testing is also more complex as the plugin must be tested too.

Approach #2 seems more complex without much quantifiable gain.


## Documentation

The documentation should be enhanced:
* Install using the RPM and the Ansible Role
* Basic Configuration
* Template
* Dry-run
* Systemd Timer
A man page must cover ipa-epn.

The WebUI [notification feature](https://pagure.io/freeipa/issue/3687) (ipapwdexpadvnotify) must be mentioned in the documentation as well.


## Testing

A small integration test can be tested and included in gating:

* Create a few users, starting with passwords expiring in the past, in the near future, in a distant future.
* Test the json output (--dry-run).
* Test the SMTP module using the local SMTP server.
* Test the SMTP module using a non-local SMTP server. 
* Set max-emails lower than the number of users whose passwords are expiring and test that no more than max-emails are sent.
* Run the tests above when the tool is installed on an IPA server.
* Run the test above when the tool is installed on an IPA client.

A larger integration test that repeat the same tests with 100K users, 30K of which have expiring passwords can be included in nightlies.


## Non-MVP User Stories and ideas

### User Stories

* As a sysadmin, I would like to be able to exclude a group from notifications. Or (possibly better):
* As a sysadmin, I would like to be able to specify a group: only users from this group will get notifications.

Note: large groups are inefficient.

### Optimization

When IPA contains a large number of users, the LDAP request can be cut in smaller requests (time ranges) by the tool itself.
For instance, twenty-four 1h time ranges can be specified for 1-day ranges, leading to a smaller amount of emails sent per batch and smaller in-memory data structures.
A configurable pause time can be specified in-between.
This avoids flooding the SMTP server (and triggering anti-DDoS systems).

### Additional knobs

* --output-type json/csv/human - only json as part of the MVP
* --output-file <path> - this is not needed (shell redirection).

### Additional configuration items

* Secure = never | SSL | STARTTLS
* Timeout
* SMTP certificate file
* SMTP key file

