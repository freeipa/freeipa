import argparse
import json

import yaml

parser = argparse.ArgumentParser(description='Generate Azure jobs matrix.')
parser.add_argument('azure_template', help='path to Azure template')

args = parser.parse_args()

with open(args.azure_template) as f:
    data = yaml.safe_load(f)
    matrix_jobs = {}
    for vm in data['vms']:
        jobs = {}
        job_name = ''
        for job_id, vm_job in enumerate(vm['vm_jobs'], 1):
            if not job_name:
                job_name = f'{vm_job["container_job"]}_{job_id}'
            jobs[f'ipa_tests_env_name_{job_id}'] = vm_job['container_job']
            jobs[f'ipa_tests_to_run_{job_id}'] = ' '.join(vm_job['tests'])
            jobs[f'ipa_tests_to_ignore_{job_id}'] = ' '.join(
                vm_job.get('ignore', ''))
            jobs[f'ipa_tests_type_{job_id}'] = vm_job.get(
                'type', 'integration')

            containers = vm_job.get('containers')
            replicas = 0
            clients = 0
            if containers:
                replicas = containers.get('replicas', 0)
                clients = containers.get('clients', 0)
            jobs[f'ipa_tests_replicas_{job_id}'] = replicas
            jobs[f'ipa_tests_clients_{job_id}'] = clients

        job_name = f'{job_name}_to_{len(vm["vm_jobs"])}'
        if job_name in matrix_jobs:
            raise ValueError(f"Environment names should be unique:{job_name}")
        matrix_jobs[job_name] = jobs
    print("##vso[task.setVariable variable=matrix;isOutput=true]" +
          json.dumps(matrix_jobs))
