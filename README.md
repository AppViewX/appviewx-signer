AppViewX Istio-k8s Signer
=================

With Kubernetes 1.18, there is [*a certification signing request (CSR) API*](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)
feature, which allows for automation of certificate request and retrieval from certification authorities. Istiod acts as the Registration Authority to manage updates for a CSR resource.

The one form of integration options of Istio with AppViewX capitalize the K8s CSR feature, where the CSR received by the Istiod is sent to the AppViewX Kubernetes signer.

The operator has the external certificate authority signer implementation which enables the CSR to be signed by any custom Certificate Authority configured in the AppViewX Cert+ product.

![AppViewX-Istio-K8s Signer](https://github.com/vigneshkathir/appviewx-signer/blob/main/images/AppViewX-Istio-K8s-Operator.jpeg)

Integration Prerequisites 
===========================
Before configuring the AppViewX-Istio K8s signer, the below prerequisites should be validated.

 - [ ] Cluster running Kubernetes with 1.18+ version.
 - [ ] Download and Install Istio version 1.8+.
 - [ ]  GO version 1.16 and above
 - [ ] Signup for [AppViewX account](https://www.appviewx.com/resources/cert-start-your-trial/)

> Note : Existing customers reach us @ help@appviewx.com

AppViewX-Istio K8s Signer Configuration
=========================================

Installation Steps
------------------

-    Download appviewx-signer from the github.com to the K8s master node
	 ```bash
     git clone https://github.com/AppViewX/appviewx-signer.git
	   ```

- Change the working directory to **appviewx-signer** and build the appviewx-signer binary.
	```bash
	cd <installdirectory>/appviewx-signer/ 
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go;
	```

-   Change the working directory to **demo**  and update the AppViewX Instance credentials and host details on the appviewx.env file.
    ```bash
     cd <installdirectory>/appviewx-signer/demo/
    ```
    > Note : Host details and credentials will be shared upon signup / registration.
 
- Create a kubernetes secret with the AppViewX environment and credentials.
	```bash
	kubectl create secret generic appviewx-credentials -n signer-ca-system --from-env-file=./appviewx.env;
	```
- Change the working directory to **appviewx-signer** and build and deploy the appviewx-signer docker image.
	```bash
	 cd <installdirectory>/appviewx-signer/;
	 make docker-build deploy-e2e DOCKER_PREFIX=appviewx-istio/appviewx-signer/ DOCKER_TAG=1.0;
	 ```
	
- Create a kubernetes secret to host the Signing Certificate Authority by concatenating the Root CA and the Intermediate CA to base64 format.
  ```bash
   cat <installdirectory>/appviewx-signer/demo/RootCA.crt <installdirectory>/appviewx-signer/demo/SUBCA.crt | base64 |  tr  -d '\n'
  ```
  > Note : Example base64 content file  **base64example.txt**  available in the demo directory.
-  Change the working directory to **demo** .
    ```bash
     cd <installdirectory>/appviewx-signer/demo/
     ```
    
-   Copy the base64 content and insert in an external-ca-cert.yaml file as below.
	  ```bash
	apiVersion: v1
	kind: Secret
	metadata:
	    name: external-ca-cert
	    namespace: istio-system
	data:
	    root-cert.pem: "BASE64 CONTENT HERE"
	  ```

-   Create the istio namespace and kubernetes secret with the command 

    > “kubectl create namespace  istio-system ; kubectl apply -f external-ca-cert.yaml”.

## Enable Custom Certificate Authority

To enable custom Certificate Authority, user can download the Root and Intermediate Certificates from AppViewX and replace existing certificates (RootCA.crt , SUBCA.crt) in the demo directory.

> Note : Applicable for existing customers. 

Install Istio and enable external signer
-----------------------------------------

The below steps are executed to install Istio on the kubernetes cluster and enable External CA integration to sign workload and ingress/egress gateway certificates.

-   Download getIstio
    ```bash
     curl -sLhttps://tetrate.bintray.com/getistio/download.sh | bash
     ```

-   Fetch Istio binary 
    ```bash
    getistio fetch
    ```

-   Enable external signer in istio configuration using the istio.yaml file like below.
	```bash
	apiVersion: install.istio.io/v1alpha1
	kind: IstioOperator
	spec:
	  components:
	    base:
	      k8s:
	        overlays:
	          # Amend ClusterRole to add permission for istiod to approve certificate signing by custom signer
	          - kind: ClusterRole
	            name: istiod-istio-system
	            patches:
	              - path: rules[-1]
	                value: |
	                  apiGroups:
	                  - certificates.k8s.io
	                  resourceNames:
	                  - example.com/foo     #Replace Signer Name
	                  resources:
	                  - signers
	                  verbs:
	                  - approve
	                  - sign
	    pilot:
	      k8s:
	        env:
	          # Indicate to Istiod that we use an external signer
	          - name: EXTERNAL_CA
	            value: ISTIOD_RA_KUBERNETES_API
	          # Indicate to Istiod the external k8s Signer Name
	          - name: K8S_SIGNER
	            value: example.com/foo     #Replace Signer Name
	        overlays:
	        - kind: Deployment
	          name: istiod
	          patches:
	            - path: spec.template.spec.containers[0].volumeMounts[-1]
	              value: |
	                # Mount external CA certificate into Istiod
	                name: external-ca-cert
	                mountPath: /etc/external-ca-cert
	                readOnly: true
	            - path: spec.template.spec.volumes[-1]
	              value: |
	                name: external-ca-cert
	                secret:
	                  secretName: external-ca-cert
	                  optional: true
	```

-   Install istio using getIstio
	```bash
	 getistio istioctl install --set profile=demo -f ./istio.yaml --set values.global.imagePullPolicy=IfNotPresent
	```
Test Environment Setup 
-----------------------

To validate and verify the mTLS certificates issued by a custom Certificate Authority, users can install a sample application using the below script and verify the custom certificate signed.

The script installs a sample httpbin and sleep application in a separate namespace called **foo** and enrolls mTLS certificates from AppViewX. Once installed the script verifies the certificate chain and displays the certificate serial number which can be cross verified in the AppViewX CERT+ inventory.

Run the below shell script.
```bash
./mTLSexternalcertvalidation.sh
```




tar -cvzf ./01-Apr-2021-12\:43\:51.tar.gz 01-Apr-2021-12\:43\:51/
