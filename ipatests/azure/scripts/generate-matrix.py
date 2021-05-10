import argparse
import copy
import pprint
import json

import yaml

parser = argparse.ArgumentParser(description='Generate Azure jobs matrix.')
parser.add_argument('azure_template', help='path to Azure template')

parser.add_argument('max_azure_env_jobs', type=int,
                    help='maximum number of Docker envs within VM')

args = parser.parse_args()

with open(args.azure_template) as f:
    data = yaml.safe_load(f)
    default_resources = data["default_resources"]
    matrix_jobs = {}
    for vm in data['vms']:
        vm_jobs = vm['vm_jobs']
        jobs = {}
        job_name = ''
        for job_id, vm_job in enumerate(vm_jobs, 1):
            if not job_name:
                job_name = f'{vm_job["container_job"]}_{job_id}'
            jobs[f'ipa_tests_env_name_{job_id}'] = vm_job['container_job']
            jobs[f'ipa_tests_to_run_{job_id}'] = ' '.join(vm_job['tests'])
            jobs[f'ipa_tests_to_ignore_{job_id}'] = ' '.join(
                vm_job.get('ignore', ''))
            jobs[f'ipa_tests_type_{job_id}'] = vm_job.get(
                'type', 'integration')
            jobs[f'ipa_tests_args_{job_id}'] = vm_job.get('args', '')
            jobs[f'ipa_tests_network_internal_{job_id}'] = vm_job.get(
                'isolated', 'false'
            )

            containers = vm_job.get('containers')
            cont_resources = copy.deepcopy(default_resources)
            replicas = 0
            clients = 0
            if containers:
                replicas = containers.get('replicas', 0)
                clients = containers.get('clients', 0)

                resources = containers.get("resources")
                if resources:
                    for cont in ["server", "replica", "client"]:
                        cont_resources[cont].update(
                            resources.get(cont, {})
                        )

            jobs[f'ipa_tests_replicas_{job_id}'] = replicas
            jobs[f'ipa_tests_clients_{job_id}'] = clients

            for cont in ["server", "replica", "client"]:
                for res in ["mem_limit", "memswap_limit"]:
                    key = f"ipa_tests_{cont}_{res}_{job_id}"
                    jobs[key] = cont_resources[cont][res]

        if len(vm_jobs) > args.max_azure_env_jobs:
            raise ValueError(
                f"Number of defined jobs:{len(vm_jobs)} within VM:'{job_name}'"
                f" is greater than limit:{args.max_azure_env_jobs}")
        job_name = f'{job_name}_to_{len(vm_jobs)}'
        if job_name in matrix_jobs:
            raise ValueError(f"Environment names should be unique:{job_name}")
        matrix_jobs[job_name] = jobs

    pprint.pprint(matrix_jobs)
    print("##vso[task.setVariable variable=matrix;isOutput=true]" +
          json.dumps(matrix_jobs))
