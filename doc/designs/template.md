# Feature name

## Overview

Short overview of the problem set and any background material or references one would need to understand the details. 

## Use Cases

Walk through one or more full examples of how the feature will be used. These should not all be the simplest cases. 

## How to Use

This a starting point for design discussions.

Easy to follow instructions how to use the new feature according to the [use cases](#use-cases) described above. FreeIPA user needs to be able to follow the steps and demonstrate the new features.

The chapter may be divided in sub-sections per [Use Case](#use-cases). 

## Design

The proposed solution. This may include but is not limited to:

- High Level schema([Example 1](https://www.freeipa.org/page/V4/OTP), [Example 2](https://www.freeipa.org/page/V4/Migrating_existing_environments_to_Trust))
- Information or update workflow
- Access control (may include [new permissions](https://www.freeipa.org/page/V4/Permissions_V2))
- Compatibility with other (older) version of FreeIPA. Think if the feature requires a minimum [Domain level](https://www.freeipa.org/page/V4/Domain_Levels).

For other hints what to consider see [general considerations](https://www.freeipa.org/page/General_considerations) page. 

## Implementation

Any implementation details you would like to spell out. Describe any technical details here. Make sure you cover

- Dependencies: any new dependencies that FreeIPA project packages would gain and that needs to be packaged in distros? The proposal needs to be carefully reviewed, so that FreeIPA dependency size does not increase without strong justification.
- Backup and Restore: any new file to back up or change required in [Backup and Restore](https://www.freeipa.org/page/V3/Backup_and_Restore)?

If this section is not trivial, move it to /Implementation sub page and only include link. 

## Feature Management

### UI

How the feature will be managed via the Web UI. 

### CLI

Overview of the CLI commands. Example:

| Command |	Options |
| --- | ----- |
| config-mod | --user-auth-type=password/otp/radius |
| user-mod | --user-auth-type=password/otp/radius --radius=STR --radius-username=STR |

### Configuration

Any configuration options? Any commands to enable/disable the feature or turn on/off its parts? 

## Upgrade

Any impact on upgrades? Remove this section if not applicable. 

## Test plan

Test scenarios that will be transformed to test cases for FreeIPA [Continuous Integration](https://www.freeipa.org/page/V3/Integration_testing) during implementation or review phase. This can be also link to source in [pagure](https://pagure.io/freeipa.git) with the test, if appropriate. 

## Troubleshooting and debugging

Include as much information as possible that would help troubleshooting:
- Does the feature rely on existing files (keytabs, config file...)
- Does the feature produce logs? in a file or in the journal?
- Does the feature create/rely on LDAP entries? 
- How to enable debug logs?
- When the feature doesn't work, is it possible to diagnose which step failed? Are there intermediate steps that produce logs?
