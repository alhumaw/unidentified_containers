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
were launched outside the control of the Kubernetes orchestrator,
then optionally deletes these containers.

This can happen when the worker nodes or Kubernetes orchestrator are compromised. 
For example, an adversary can use a compromised node to directly run a container, 
then download a malicious tool in the container to compromise the entire infrastructure. 

Because this malicious container wasn’t launched using Kubernetes, it isn’t visible to Kubernetes. 
Such containers launched directly on a Kubernetes-managed node should be investigated.

Developed by @alhumaw

"""
import json
import os
import logging
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
from falconpy import APIHarnessV2, APIError

try:
    from termcolor import colored
except ImportError as no_termcolor:
    raise SystemExit("The termcolor library must be installed.\n"
                     "Install it with `python3 -m pip install termcolor"
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
    parser.add_argument("-v", "--verbose",
                        help="Display additional information about the containers.",
                        )
    parser.add_argument("-Id", "--identifier",
                        help="Select a specific pod_id")
    
    parsed = parser.parse_args()

    return parsed

class Pod:
    def __init__(self, podID) -> None:
        
        self.podID = podID
        self.containers = []
        self.unassessedImages = []
        self.detectionTimestamp = ""
        self.risk = ""
        self.name = ""
        self.visible = False

    def __str__(self) -> str:
        return tabulate([["Pod Name", self.name] if self.name else None,
                         ["Containers", self.containers],
                         ["Unassessed Images", self.unassessedImages],
                         ["Severity", self.risk],
                         ["Visible to k8s", self.visible]], 
                         tablefmt="heavy_grid")

def get_pods(falcon: APIHarnessV2) -> list:
    pods = []
    resp = falcon.command("SearchAndReadUnidentifiedContainers")['body']['resources']
    for pod in resp:
        cur_pod = Pod(pod.get('pod_id'))
        
        # Retrieve impacted containers
        containers = pod.get('containers_impacted')
        for cur_container in containers:
            cur_pod.containers.append(cur_container.get('container_id'))
        
        # Retrieve unique unassessed images
        images = pod.get('unassessed_images')
        for cur_image in images:
            imageName = cur_image.get('image_name')
            if imageName not in cur_pod.unassessedImages:
                cur_pod.unassessedImages.append(imageName)
        
        cur_pod.detectionTimestamp = pod.get('detect_timestamp')
        cur_pod.risk = pod.get('severity')
        cur_pod.name = pod.get('pod_name')
        cur_pod.visible = pod.get('visible_to_k8s') if pod.get('visible_to_k8s') == "Yes" else False

        pods.append(cur_pod)
    return pods
        

def delete_containers():
    pass

def write_file():
    pass

def connect_api(key: str, secret: str, debug: bool):
    """Connects and returns an instance of the Uber class."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    return APIHarnessV2(client_id=key, client_secret=secret, debug=debug)

def main():
    """Execute main routine."""
    args   = parse_command_line()
    falcon = connect_api(key=args.key,secret=args.secret, debug=False)
    pods   = get_pods(falcon)
    print(WHALE)
    if not args.identifier:  
        print(f"Found {len(pods)} pods, use -Id to examine a specific pod")
        for pod in pods:
            if not pod.podID:

            table = [["Pod ID",pod.podID],
                     ["Number of Unidentified Containers", len(pod.containers)],
                     ["Severity", pod.risk]]
            print(tabulate(table, tablefmt="heavy_grid"))

if __name__ == "__main__":
    main()