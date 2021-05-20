import yaml

PRCI_GATING = "ipatests/prci_definitions/gating.yaml"
AZURE_GATING = "ipatests/azure/azure_definitions/gating.yml"

prci_tests = []
azure_tests = []

SKIP_IN_AZURE_LIST = [
    "test_integration/test_authselect.py",  # requires external DNS
]

EXTRA_AZURE_LIST = []

with open(PRCI_GATING) as f:
    prci_gating = yaml.safe_load(f)
    for task in prci_gating["jobs"].values():
        job = task["job"]
        if job["class"] == "RunPytest":
            prci_tests.extend(job["args"]["test_suite"].split())

    prci_tests.sort()

with open(AZURE_GATING) as f:
    azure_gating = yaml.safe_load(f)
    for vm_jobs in azure_gating["vms"]:
        for job in vm_jobs["vm_jobs"]:
            azure_tests.extend(job["tests"])

    azure_tests.sort()

missing_in_azure = set(prci_tests) - set(azure_tests + SKIP_IN_AZURE_LIST)
if missing_in_azure:
    print(
        "##vso[task.logissue type=warning]"
        "Missing gating tests in Azure Pipelines, compared to PR-CI",
        missing_in_azure,
    )

extra_in_azure = set(azure_tests) - set(prci_tests + EXTRA_AZURE_LIST)
if extra_in_azure:
    print(
        "##vso[task.logissue type=warning]"
        "Extra gating tests in Azure Pipelines, compared to PR-CI",
        extra_in_azure,
    )
