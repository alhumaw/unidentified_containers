# Unidentified Containers

## Overview

This Python script identifies containers tracked by the Falcon Sensor that were launched outside the control of the Kubernetes orchestrator. It can optionally delete these containers, which is useful for detecting potential security breaches or misconfigurations in your Kubernetes environment.

## Why This Matters

Containers launched outside of Kubernetes control can indicate:
- Compromised worker nodes or Kubernetes orchestrator
- Potential adversary activity, such as running malicious containers directly on a node
- Security misconfigurations

Such containers are not visible, making them a potential security risk that should be investigated.

## Features

- Identifies containers not launched by Kubernetes
- Provides detailed information about unidentified containers
- Option to delete specific or all unidentified containers
- Integrates with CrowdStrike Falcon API for container information retrieval

## Requirements

- Python 3.x
- CrowdStrike Falcon API credentials
- Required Python libraries: 
  - falconpy
  - termcolor
  - tabulate

## Installation

1. Clone this repository
2. Install required libraries:
`pip install falconpy tqdm termcolor tabulate`

## Usage

Basic usage:
`python3 unidentified_container_detector.py -k YOUR_API_KEY -s YOUR_API_SECRET`

## Output

The script provides a summary of unidentified containers found, including:
- Total number of affected pods
- Total number of unidentified containers
- Detailed information for each pod (when using the `-i` option)
