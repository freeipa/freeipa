#! /usr/bin/python3
import os
import glob
import sys
import argparse
from argparse import RawTextHelpFormatter
import yaml

# Get default DIR from script location
DEFAULT_DIR = os.path.dirname(os.path.abspath(__file__))
# Default jobs specification file name and path
JOBS_SPEC_YAML = "prci_jobs_spec.yaml"
JOBS_SPEC_PATH = os.path.join(DEFAULT_DIR, JOBS_SPEC_YAML)
# Files to ignore on check
IGNORE_FILES = {JOBS_SPEC_YAML, "temp_commit.yaml"}


def load_yaml(path):
    """Load YAML file into Python object."""
    with open(path, "r") as file_data:
        data = yaml.safe_load(file_data)

    return data


def print_error(msg):
    """Helper function to print error messages"""
    print("ERROR: " + msg)


def print_warning(msg):
    """Helper function to print warning messages"""
    print("WARNING: " + msg)


def print_hint(msg):
    """Helper function to print hint messages"""
    print("HINT: " + msg)


def print_field_error(
    jobname, fieldname=None, expected_value=None, custom_msg=None
):
    """Helper function to print field errors"""
    msg = f"In job '{jobname}':\n"
    if custom_msg:
        msg += f"  {custom_msg}"
    elif fieldname and expected_value:
        msg += (
            f'  Job field "{fieldname}" should be defined as: '
            f'"{fieldname}: {expected_value}"'
        )
    else:
        msg = f"In job '{jobname}'."
    print_error(msg)


def check_jobs(filename, jobs_def, topologies, current_spec, supported_classes):
    """
    Check if given job definition file has all jobs correctly defined according
    to specification file.

    :param filename: file name of the definition file to be checked
    :param jobs_def: definition file jobs as a dict object
    :param topologies: list of dicts of predefined topologies
    :param jobs_spec: PRCI specification file containing correct definitions
    :param supported_classes: List of supported test-run classes

    :returns: Boolean with the checks result
    """
    correct_fields = True

    try:
        job_prefix = current_spec["job_prefix"]
    except KeyError as e:
        print_error(
            "Specification file has bad format "
            f"and '{filename}' could not be analyzed.\n"
            f"  KeyError: {e} in '{filename}'"
        )
        return False

    requires = [f"{job_prefix}build"]
    build_url = f"{{{job_prefix}build_url}}"

    # Get template from build job
    build_job_name = job_prefix + "build"
    build_job = jobs_def.get(build_job_name)
    if not build_job:
        print_error(
            " Build job is not defined or has incorrect name.\n"
            f"  Name should be: '{build_job_name}'"
        )
        return False
    build_args = build_job["job"]["args"]
    template = build_args["template"]

    copr = build_args.get("copr")
    copr_defined = current_spec.get("copr_defined", False)

    update_packages = current_spec.get("update_packages", False)
    selinux = current_spec.get("selinux_enforcing", False)
    enable_testing_repo = current_spec.get("enable_testing_repo", False)

    for job_name, params in jobs_def.items():
        # Checks for all kind of jobs
        args = params.get("job").get("args")
        if not job_name.startswith(job_prefix):
            msg = f"Job name should start with prefix '{job_prefix}'"
            print_field_error(job_name, custom_msg=msg)
            correct_fields = False
        if args.get("template") != template:
            print_field_error(job_name, "template", template)
            correct_fields = False
        if "timeout" not in args:
            msg = "'timeout' field should be defined in args section"
            print_field_error(job_name, custom_msg=msg)
            correct_fields = False
        if args.get("topology") not in topologies:
            msg = (
                "'topology' field should be defined with one of the "
                "pre-defined topologies"
            )
            print_field_error(job_name, custom_msg=msg)
            correct_fields = False
        if args.get("enable_testing_repo", False) != enable_testing_repo:
            if enable_testing_repo:
                print_field_error(
                    job_name, "enable_testing_repo", enable_testing_repo
                )
            else:
                msg = (
                    "'enable_testing_repo' field should be set to false or not"
                    " defined"
                )
                print_field_error(job_name, custom_msg=msg)
            correct_fields = False

        # Checks for build job
        if job_name == build_job_name:
            if copr_defined and not copr:
                msg = "'copr' field should be defined for the build job"
                print_field_error(job_name, custom_msg=msg)
                correct_fields = False
            elif not copr_defined and copr:
                msg = "'copr' field should NOT be defined for the build job"
                print_field_error(job_name, custom_msg=msg)
                correct_fields = False
            if params.get("job").get("class") != "Build":
                print_field_error(job_name, "class", "Build")
                correct_fields = False
            continue

        # Checks only for non-build jobs
        if params.get("requires") != requires:
            print_field_error(job_name, "requires", requires)
            correct_fields = False
        if params.get("job").get("class") not in supported_classes:
            msg = (
                "'class' field should be defined with one of the "
                f"supported: {supported_classes}"
            )
            print_field_error(job_name, custom_msg=msg)
            correct_fields = False
        if args.get("build_url") != build_url:
            print_field_error(job_name, "build_url", f"'{build_url}'")
            correct_fields = False
        if "test_suite" not in args:
            msg = "'test_suite' field should be defined in args section"
            print_field_error(job_name, custom_msg=msg)
            correct_fields = False
        # Check template field against build target
        if args.get("template") != template:
            print_field_error(job_name, "template", template)
            correct_fields = False
        # If build target has a copr repo, check that the job also defines it
        if args.get("copr") != copr:
            if copr and copr_defined:
                print_field_error(job_name, "copr", copr)
            elif not copr and not copr_defined:
                msg = "'copr' field should not be defined"
                print_field_error(job_name, custom_msg=msg)
            correct_fields = False
        if args.get("update_packages", False) != update_packages:
            if update_packages:
                print_field_error(job_name, "update_packages", update_packages)
            else:
                msg = (
                    "'update_packages' field should be set to false or not"
                    " defined"
                )
                print_field_error(job_name, custom_msg=msg)
            correct_fields = False
        if args.get("selinux_enforcing", False) != selinux:
            if selinux:
                print_field_error(job_name, "selinux_enforcing", selinux)
            else:
                msg = (
                    "'selinux_enforcing' field should be set to false or not"
                    " defined"
                )
                print_field_error(job_name, custom_msg=msg)
            correct_fields = False

    return correct_fields


def process_def_file(file, jobs_spec, supported_classes):
    """Function to process PRCI definition file

    :param file: name of the definition file to be
                 processed (extension included)
    :param jobs_spec: PRCI specification file containing correct definitions
    :param supported_classes: List of supported test-run classes

    :returns: Boolean with the checks result, filename,
              and number of jobs in the definition
              file (-1 when error / warning)
    """
    # File base name without extension
    filename = os.path.splitext(os.path.basename(file))[0]
    try:
        def_suite = load_yaml(file)
    except FileNotFoundError as e:
        print(e)
        print_error(f"File '{file}' was not found.")
        sys.exit(1)
    except yaml.composer.ComposerError as e:
        print_error(str(e))
        print_hint(
            "You probably defined a wrong alias "
            "in the newly added or modified job."
        )
        sys.exit(1)
    except yaml.YAMLError as e:
        print(e)
        print_error(f"Error loading YAML definition file {file}")
        sys.exit(1)

    # Get spec for file to be analyzed
    current_spec = jobs_spec.get(filename)
    if current_spec is None:
        print_warning(
            f"'{filename}' file is not defined in the PRCI "
            "specification file and "
            "could not be analyzed."
        )
        return True, "", -1

    jobs_def = def_suite.get("jobs")
    if jobs_def is None:
        print_error(
            f"'{filename}' file doesn't have a jobs section following "
            "the format."
        )
        return False, "", -1

    # Get list of pre-defined topologies
    topologies_def = def_suite.get("topologies")
    if topologies_def is None:
        print_error(
            f"'{filename}' file doesn't have a topologies section following "
            "the format."
        )
        return False, "", -1
    topologies = list(topologies_def.values())

    # Print file to be analyzed and its number of jobs
    n_jobs = len(jobs_def)
    print("[File] " + filename + " [Jobs] " + str(n_jobs))

    result = check_jobs(
        filename, jobs_def, topologies, current_spec, supported_classes
    )
    return result, filename, n_jobs


def process_spec_file(filepath):
    """Function to process jobs specification file

    :param filepath: Filepath for spec file

    :returns: Definition specification dict, supported classes and
              list of files that should contain the same number of jobs
    """
    try:
        spec_root = load_yaml(filepath)
    except FileNotFoundError as e:
        print(e)
        print_error(f"Jobs specification file '{filepath}' not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(e)
        print_error(f"Error loading YAML specification file '{filepath}'")
        sys.exit(1)

    jobs_spec = spec_root.get("prci_job_spec")
    if not jobs_spec:
        print_error(
            f"Specification definition not found in spec file '{filepath}'\n"
            "  Key 'prci_job_spec' is not present."
        )
        sys.exit(1)

    supported_classes = spec_root.get("classes")
    if not supported_classes:
        print_error(
            f"Supported classes not defined in spec file '{filepath}'\n"
            "  Key 'classes' is not present."
        )
        sys.exit(1)

    f_fixed_jobs = spec_root.get("fixed_n_jobs")

    return jobs_spec, supported_classes, f_fixed_jobs


def check_n_jobs(defs_n_jobs):
    """
    Function to check if definition files have the same number of jobs

    :param defs_n_jobs: Dict of definition filenames as keys and number
                        of jobs as values

    :returns: Boolean, if definitions have the same number of jobs
    """
    if not defs_n_jobs:  # Spec not defined to check num of jobs
        return True
    elif len(set(defs_n_jobs.values())) == 1:
        return True
    else:
        print_error(
            "Following PRCI definitions should have the same number of jobs:"
            f" {list(defs_n_jobs.keys())}"
        )
        return False


def parse_arguments(description):
    """Parse and return arguments if specified"""
    parser = argparse.ArgumentParser(
        description=description, formatter_class=RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-f", "--file", help="Specify YAML definition file to be analyzed"
    )
    group.add_argument(
        "-d",
        "--defs",
        default=DEFAULT_DIR,
        help="Specify directory for definition files to be analyzed",
    )
    parser.add_argument(
        "-s",
        "--spec",
        default=JOBS_SPEC_PATH,
        help="Specify path for specification file",
    )
    return parser.parse_args()


def main():
    """
    Checker script for prci definition files.\n
    This script checks whether jobs in a prci definition file have the correct
    naming format, requirements, and arguments, which are defined in the
    specification file.

    If no defition file, definition directory or spec file is specified,
    script will look for them in its own dir location.

    Examples of the usage for the tool:\n
    # Check all yaml definition files in default dir\n
    python3 prci_checker.py\n
    # Check only specified file\n
    python3 prci_checker.py -f gating.yaml\n
    # Check with custom path for spec file\n
    python3 prci_checker.py -s ../../alternative_spec.yaml
    # Check with custom path for spec file\n
    python3 prci_checker.py -d ./definitions

    Find more examples of how to use the tool and spec file
    at https://freeipa.readthedocs.io/en/latest/designs/index.html
    """
    args = parse_arguments(main.__doc__)

    print("BEGINNING PRCI JOB DEFINITIONS CHECKS")

    # Get data from jobs specification file
    jobs_spec, supported_classes, f_fixed_jobs = process_spec_file(args.spec)

    if args.file:
        result = process_def_file(args.file, jobs_spec, supported_classes)[0]
    else:
        # Get all yaml files in default dir, except those in IGNORE_FILES
        def_files_dir = os.path.join(args.defs, "*.y*ml")
        defs_files = glob.glob(def_files_dir)
        ignore_files_paths = {
            os.path.join(args.defs, ignore_file) for ignore_file in IGNORE_FILES
        }
        defs_files = set(defs_files) - ignore_files_paths
        if not defs_files:
            print_warning(
                "No yaml job definition files found to analyze "
                "in specified directory."
            )
            return

        result = True
        defs_n_jobs = {}

        for def_file in defs_files:
            result_file, filename, n_jobs = process_def_file(
                def_file, jobs_spec, supported_classes
            )
            if not result_file:
                result = False
                continue
            if n_jobs > -1 and f_fixed_jobs and filename in f_fixed_jobs:
                defs_n_jobs[filename] = n_jobs

        result = result and check_n_jobs(defs_n_jobs)

    if not result:
        print("CHECKS FINISHED WITH ERRORS")
        sys.exit(1)

    print("CHECKS FINISHED SUCCESSFULLY")


if __name__ == "__main__":
    main()
