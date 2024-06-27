#!/usr/bin/env python3
"""
 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |                         |::.. . |           FalconPy
`-------'                         `-------'                         

This sample identifies containers tracked by the Falcon Sensor that 
were launched outside the control of the Kubernetes orchestrator.

This can happen when the worker nodes or Kubernetes orchestrator are compromised. 
For example, an adversary can use a compromised node to directly run a container, 
then download a malicious tool in the container to compromise the entire infrastructure. 

Because this malicious container wasn’t launched using Kubernetes, it isn’t visible to Kubernetes. 
Such containers launched directly on a Kubernetes-managed node should be investigated.

Use the Unidentified containers dashboard (Investigate > Unidentified containers) 
to quickly identify runtime container workloads with an unauthorized image 
(one that has not been assessed in Image Assessment for vulnerabilities and malware) 
and containers launched outside the Kubernetes orchestrator.

Developed by @alhumaw

"""
import re
import json
import os
import logging
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
from falconpy import APIHarnessV2, APIError
try:
    from termcolor import colored
except ImportError as no_termcolor:
    raise SystemExit("The termcolor library must be installed.\n"
                     "Install it with `python3 -m pip install termcolor`"
                     ) from no_termcolor
try:
    from tabulate import tabulate
except ImportError as no_tabulate:
    raise SystemExit("The tabulate library must be installed.\n"
                     "Install it with `python3 -m pip install tabulate`."
                     ) from no_tabulate

WHALE = r"""

                          o
         .-'               o
    '--./ /     _.---.    o
    '-,  (__..-`       \   o
       \          x     | o
        `,.__.   ,__.--/
          '._/_.'___.-`
    ~^~^~^~^~^~^~^~^~^~^~^~^~^      
    """


def parse_command_line() -> ArgumentParser:
    """Parses the passed command line and returns the created args object."""
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    required = parser.add_argument_group("required arguments")
    required.add_argument("-k", "--key",
                          help="CrowdStrike Falcon API Client ID",
                          required=True
                          )

    required.add_argument("-s", "--secret",
                          help="CrowdStrike Falcon API Client Secret",
                          required=True
                          )

    parser.add_argument("-d", "--delete",
                        help="Delete a specific unidentified container.",
                        )

    parser.add_argument("-da", "--delete-all",
                        help="Delete all unidentified containers.",
                        )

    parser.add_argument("-i", "--identifier",
                        help="Select a specific pod_id")
    
    parser.add_argument("-t", "--sort-timestamp",
                        help="Sort by most recent detection")

    parser.add_argument("-de", "--debug",
                        help="View API debugger",
                        default=False,
                        action="store_true")

    parsed = parser.parse_args()

    return parsed

class Pod:
    """Class used to organize pods and their respective elements.

    :param pod_id: The identifier for the pod
    
    """
    def __init__(self, pod_id) -> None:

        self.pod_id = pod_id
        self.containers = []
        self.unassessed_images = []
        self.detection_timestamp = ""
        self.risk = ""
        self.name = ""
        self.visible = False

    def container_count(self):
        """Returns the amount of containers in the pod"""
        return len(self.containers)

    def __str__(self) -> str:
        return tabulate([["Pod Name", self.name] if self.name else None,
                         ["Unassessed Images", '\n'.join(self.unassessed_images)],
                         ["Severity", self.risk],
                         ["Visible to k8s", self.visible],
                         ["Unidentfied Containers", len(self.containers)],
                         ["Containers", '\n'.join(self.containers)]],
                         tablefmt="heavy_grid")

def get_pods(falcon: APIHarnessV2) -> list[Pod]:
    """Parses API response to build Pods. Returns a list of Pods."""
    pods = []
    resp = falcon.command("SearchAndReadUnidentifiedContainers")['body']['resources']
    skip_image = "quay.io/crowdstrike/detection-container:latest"
    assessed_images = []
    for pod in resp:

        cur_pod = Pod(pod.get('pod_id', None))

        # Retrieve impacted containers
        containers = pod.get('containers_impacted')
        for cur_container in containers:
            cur_pod.containers.append(cur_container.get('container_id'))

        # Retrieve unique unassessed images
        images = pod.get('unassessed_images')
        for cur_image in images:
            image_name = cur_image.get('image_name')
            if image_name not in cur_pod.unassessed_images:
                cur_pod.unassessed_images.append(image_name)

        # Retrieve asssessed images
        assessed_image = pod.get('assessed_images')
        for cur_image in assessed_image:
            a_image = cur_image.get('image_name')
            if a_image == skip_image:
                assessed_images.append(a_image)

        cur_pod.detection_timestamp = pod.get('detect_timestamp')
        cur_pod.risk    = pod.get('severity')
        cur_pod.name    = pod.get('pod_name')
        cur_pod.visible = pod.get('visible_to_k8s') if pod.get('visible_to_k8s') == "Yes" else False


        if (len(cur_pod.containers) > 0) and len(assessed_images) == 0:
            pods.append(cur_pod)

    return pods

def delete_containers():
    # TODO: Implement function
    pass

def write_file():
    # TODO: Implement function
    pass

def connect_api(key: str, secret: str, debug: bool) -> APIHarnessV2:
    """Connects and returns an instance of the Uber class."""
    try:
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        return APIHarnessV2(client_id=key, client_secret=secret, debug=debug)
    except APIError as e:
        print(f"Failed to connect to API: {e}")
        

def sum_containers(pods: Pod) -> int:
    """Returns the total number of all containers"""
    count = 0
    for pod in pods:
        count += int(pod.container_count())
    return count

def search_result(identifier: str, pods: Pod) -> None:
    """Identifies the pod being referenced by user"""
    found = False
    pattern = r'^([a-z]|[0-9]){8}-(([a-z]|[0-9]){4}-){3}([a-z]|[0-9]){12}'
    pattern = re.compile(pattern)
    if not pattern.match(identifier):
        print("Invalid ID format, EX: 98e6v56a-a899-4f1b-acd7-333202aee88d")
    else:
        for pod in pods:
            if pod.pod_id == identifier:
                print(pod)
                found = True
        if not found:
            print(f"Could not find Pod using Pod ID: {identifier}")


def print_pod_overview(pods: Pod) -> None:
    """Prints an overview of all pods, their respective container counts, and the severity"""
    num_pods = colored(len(pods),"red")
    num_containers = colored(sum_containers(pods),"red")
    tables = []
    rogue_containers = []
    headers = ["Pod ID","Containers","Severity"]
    print(colored(f"Found {num_pods} "
                      f"{colored('pods with',"yellow")} {num_containers} "
                      f"{colored('unidentified containers, use -i to examine a specific pod','yellow')}\n", "yellow"))
    for pod in pods:
        if not pod.pod_id:
            rogue_containers.append(pod)
        else:
            table = [pod.pod_id,
                    len(pod.containers),
                    pod.risk]
            tables.append(table)
    print(tabulate(tables,headers,tablefmt="heavy_grid", colalign=("left", "left", "left")))


def main():
    """Execute main routine."""
    print(colored(WHALE, "blue"))
    args   = parse_command_line()
    falcon = connect_api(key=args.key,secret=args.secret, debug=args.debug)
    pods   = get_pods(falcon)

    if args.identifier:
        search_result(args.identifier, pods)
    else:
        print_pod_overview(pods)


if __name__ == "__main__":
    main()
