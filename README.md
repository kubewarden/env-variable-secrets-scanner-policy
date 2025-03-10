[![Kubewarden Policy Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-policies.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#policy-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# Kubewarden policy env-variable-secrets-scanner-policy

## Description

This policy will reject pods that contain a secret in an environment variable in any container. It scans environment 
variables in all containers, init containers and ephemeral containers. The policy can detect secrets that are leaked via base64 encoded variables.
The policy looks for the following secrets being leaked: RSA private keys, SSH private keys and API tokens for different services like Slack, Facebook tokens, AWS, Google, New Relic Keys, etc.

This policy is powered by the same rule engine used by [rusty hog](https://github.com/newrelic/rusty-hog), an open source secret scanner from New Relic.

The policy can either target `Pods`, or [workload
resources](https://kubernetes.io/docs/concepts/workloads/) (`Deployments`,
`ReplicaSets`, `DaemonSets`, `ReplicationControllers`, `Jobs`, `CronJobs`) by
setting the policy's `spec.rules` accordingly.

Both have trade-offs:
* Policy targets Pods: Different kind of resources (be them native or CRDs) can
  create Pods. By having the policy target Pods, we guarantee that all the Pods
  are going to be compliant, even those created from CRDs.
  However, this could lead to confusion among users, as high level Kubernetes
  resources would be successfully created, but they would stay in a non
  reconciled state. Example: a Deployment creating a non-compliant Pod would be
  created, but it would never have all its replicas running.
* Policy targets workload resources (e.g: Deployment): the policy inspect higher
  order resource (e.g. Deployment): users will get immediate feedback about
  rejections.
  However, non compliant pods created by another high level resource (be it
  native to Kubernetes, or a CRD), may not get rejected.

## Settings

This policy has no configurable settings.
