####
<img src="https://github.com/tonedefdev/kubecsr/blob/dev/img/kubecsr_logo.png" width="350" height="300">

A lightweight REST service written in `Go` leveraging the `Gin` framework that automates the toil of creating `Kubernetes` x509 certificates for users. KubeCSR is meant to make the entire process super simple and performs the following functions in one swift action:
- Creates an x509 Certificate Request (CSR) and a 2048-bit RSA Private Key
- Generates and submits a Kubernetes CSR leveraging an administrative base64 encoded `Kubeconfig` passed into the request body
- Automatically approves the Kubernetes CSR
- Pulls the approved user certificate from the `Kubernetes` CSR
- Extracts details like the cluster, server address, certificate CA, and other info from the administrative `Kubeconfig`
- Returns a freshly generated base64 encoded user `Kubeconfig` that can be decoded and used to authenticate with the target `Kubernetes` cluster

## Basic Example
```json
{
    "certificateRequest": {
        "user": "timmy"   
    },
    "kubeconfig": "<BASE64_ENCODED_ADMIN_KUBECONFIG>"
}
```

## Full Example wtih Groups
> This example will create the `Kubernetes` user `linda` who will be part of the `devops` group. If using `RBAC` then `Kubernetes` roles and rolebindings can then be associated with the `devops` group so that `linda` would inherit the permissions from anywhere that `devops` is assigned.
```json
{
    "certificateRequest": {
        "country": [
            "United States"
        ],
        "locality": [
            "Los Angeles"
        ],
        "organization": [
            "devops"
        ],
        "organizationUnit": [
            "IT"
        ],
        "postalCode": [
            "55555"
        ],
        "streetAddress": [
            "123 Main St."
        ],
        "user": "linda"   
    },
    "kubeconfig": "<BASE64_ENCODED_ADMIN_KUBECONFIG>"
}
```