# FreeIPA Pull Request CI (PR-CI) checker tool

[PR-CI checker](https://github.com/freeipa/freeipa/blob/master/ipatests/prci_definitions/prci_checker.py) is a developer tool (not shipped along FreeIPA) which checks that FreeIPA PR-CI definition files follow a pre-defined convention such as having the correct naming pattern, requirements and arguments.

The prci_definitions directory contains multiple test definition files:
- For gating: Only a subset of tests, the ones that are executed for each pull request.
- For temp commit: This is a template allowing to run a single test, usually to demonstrate that changes done to this test are working.
- For nightly tests. There are some general purpose nightlies (for instance on the master branch, we have a nightly run for fedora latest, another one for fedora previous, another one with selinux etc...) or more specialized ones, to test integration with the latest code of specific components (389ds, sssd or pki). The general purpose nightlies execute all the tests, whereas the specific nightlies execute only a subset of tests, the ones more relevant for the component.


The main purpose of the tool is to check the format of newly added or modified jobs in the PR-CI definitions.

## Basic usage

**To check all the definitions**:

``` bash
$ python3 ipatests/prci_definitions/prci_checker.py
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] nightly_previous [Jobs] 149
[File] nightly_latest_pki [Jobs] 75
[File] gating [Jobs] 24
[File] nightly_rawhide [Jobs] 149
[File] nightly_latest_389ds [Jobs] 45
[File] nightly_latest [Jobs] 149
[File] nightly_latest_selinux [Jobs] 149
[File] nightly_latest_testing [Jobs] 149
[File] nightly_latest_sssd [Jobs] 16
[File] nightly_latest_testing_selinux [Jobs] 149
CHECKS FINISHED SUCCESSFULLY
```

**alternatively:**

``` bash
$ make yamllint
[...]
Check PRCI definitions
-----------
/usr/bin/python ./ipatests/prci_definitions/prci_checker.py -d ./ipatests/prci_definitions -s ./ipatests/prci_definitions/prci_jobs_spec.yaml;
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] nightly_previous [Jobs] 149
[...]
[File] nightly_latest_testing_selinux [Jobs] 149
CHECKS FINISHED SUCCESSFULLY
-----------
```

**To check a specific file:**

``` bash
$ python3 ipatests/prci_definitions/prci_checker.py -f ipatests/prci_definitions/gating.yaml
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] gating [Jobs] 24
CHECKS FINISHED SUCCESSFULLY
```

## Tool specification file

Most part of the checks carried out by the script are described in the specification file [prci_jobs_spec.yaml](https://github.com/freeipa/freeipa/blob/master/ipatests/prci_definitions/prci_jobs_spec.yaml).

The yaml file contains supported classes, definitions that should have the same number of jobs, and format specification for each file.

**File content can vary according to the different needs in every branch**. [Example](https://github.com/freeipa/freeipa/blob/ipa-4-10/ipatests/prci_definitions/prci_jobs_spec.yaml) (taken from master branch):

``` yaml
# Specification file for PRCI definitions used by prci_checker script

# List of supported test-run classes for non-build jobs
classes:
  - "RunPytest"
  - "RunPytest2"
  - "RunPytest3"
  - "RunWebuiTests"
  - "RunADTests"
  - "RunMultiDomainPytest"

# (Optional) Definition files that should contain the same number of jobs
fixed_n_jobs:
  - nightly_latest
  - nightly_latest_selinux
  - nightly_latest_testing
  - nightly_latest_testing_selinux
  - nightly_previous
  - nightly_rawhide

# Info specific to prci definition files
# 'job_prefix' field is mandatory
# 'update_packages', 'selinux_enforcing', 'enable_testing_repo' and
# 'copr_defined' are supported but optional boolean fields (if not specified,
# false value is assumed).
# New definitions specifications may be added anytime
prci_job_spec:
  gating:
    job_prefix: 'fedora-latest/'
  nightly_latest:
    job_prefix: 'fedora-latest/'
  nightly_latest_389ds:
    job_prefix: '389ds-fedora/'
    update_packages: True
    copr_defined: True
  nightly_latest_pki:
    job_prefix: 'pki-fedora/'
    update_packages: True
    copr_defined: True
  nightly_latest_selinux:
    job_prefix: 'fedora-latest/'
    selinux_enforcing: True
  nightly_latest_testing:
    job_prefix: 'testing-fedora/'
    update_packages: True
    enable_testing_repo: True
  nightly_latest_testing_selinux:
    job_prefix: 'testing-fedora/'
    selinux_enforcing: True
    update_packages: True
    enable_testing_repo: True
  nightly_previous:
    job_prefix: 'fedora-previous/'
  nightly_rawhide:
    job_prefix: 'fedora-rawhide/'
    update_packages: True
  nightly_latest_sssd:
    job_prefix: 'sssd-fedora/'
    update_packages: True
    copr_defined: True
```

Let's see how the file specific checks work. Currently the supported fields are:

Required:
- `job_prefix`

Optional:
- `update_packages`
- `selinux_enforcing`
- `enable_testing_repo`
- `copr_defined`

Let's take an example with `nightly_latest_389ds` definition:
``` yaml
nightly_latest_389ds:
  job_prefix: '389ds-fedora/'
  update_packages: True
  copr_defined: True
```

The specifications shown above mean that every job defined in nightly_latest_389ds must:
- Have a name starting with `389ds-fedora/`
- Define `update_packages: True` and `copr_defined: True` <br>

  > **Reason**: Since the file is testing with a copr repo for 389ds, the test must call dnf update  in order to update the package to the version provided in the copr repo. Otherwise they
  would run with a wrong version of 389ds and would not properly test the integration. Likewise, if they define update_packages but do not set any copr repo, the wrong packages would be used.

On top of the above requirements, job class should also be one of the supported (listed in prci_jobs_spec.yaml).

For instance, the following would be a well formed job:
``` yaml
389ds-fedora/simple_replication:
  requires: [389ds-fedora/build]
  priority: 50
  job:
    class: RunPytest
    args:
      build_url: '{389ds-fedora/build_url}'
      update_packages: True
      copr: '@389ds/389-ds-base-nightly'
      test_suite: test_integration/test_simple_replication.py
      template: *ci-master-latest
      timeout: 3600
      topology: *master_1repl
```


## Error cases examples

After adding new jobs to the definition or editing the content, it is common that a developer has made some mistakes following the convention. This checker will help us correcting these errors. Examples:

###   Wrong or unsupported class:

``` bash
$ python3 ipatests/prci_definitions/prci_checker.py -f ipatests/prci_definitions/gating.yaml
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] gating [Jobs] 24
ERROR: In job 'fedora-latest/test_installation_TestInstallMaster':
  'class' field should be defined with one of the supported: ['RunPytest', 'RunPytest2', 'RunPytest3', 'RunWebuiTests', 'RunADTests', 'RunMultiDomainPytest']
CHECKS FINISHED WITH ERRORS
```

### Wrong job prefix in gating:

``` bash
$ python3 ipatests/prci_definitions/prci_checker.py -f ipatests/prci_definitions/gating.yaml
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] gating [Jobs] 24
ERROR: In job 'fedora-latdest/test_installation_TestInstallMaster':
  Job name should start with prefix 'fedora-latest/'
CHECKS FINISHED WITH ERRORS
```

### Wrong or missing parameter values.
E.g.
1. Missing `selinux_enforcing: True` in selinux job definition:

``` bash
$ python3 ipatests/prci_definitions/prci_checker.py -f ipatests/prci_definitions/nightly_latest_selinux.yaml
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] nightly_latest_selinux [Jobs] 149
ERROR: In job 'fedora-latest/simple_replication':
  Job field "selinux_enforcing" should be defined as: "selinux_enforcing: True"
CHECKS FINISHED WITH ERRORS
```

2. Field `topology` is not defined with one of the pre-defined templates:

``` bash
$ python prci_checker.py -f gating.yaml
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] gating [Jobs] 24
ERROR: In job 'fedora-latest/test_external_ca_TestSelfExternalSelf':
  'topology' field should be defined with one of the pre-defined topologies
CHECKS FINISHED WITH ERRORS
```

### Uneven number of jobs between definition files defined by spec file:

``` bash
$ python3 ipatests/prci_definitions/prci_checker.py
BEGINNING PRCI JOB DEFINITIONS CHECKS
[File] nightly_latest_pki [Jobs] 75
[File] nightly_latest [Jobs] 148
[File] nightly_latest_testing [Jobs] 149
[File] nightly_rawhide [Jobs] 149
[File] gating [Jobs] 24
[File] nightly_latest_selinux [Jobs] 149
[File] nightly_latest_testing_selinux [Jobs] 149
[File] nightly_latest_sssd [Jobs] 16
[File] nightly_latest_389ds [Jobs] 45
[File] nightly_previous [Jobs] 149
ERROR: Following PRCI definitions should have the same number of jobs: ['nightly_latest', 'nightly_latest_testing', 'nightly_rawhide', 'nightly_latest_selinux', 'nightly_latest_testing_selinux', 'nightly_previous']
CHECKS FINISHED WITH ERRORS
```
