# Deploying the controller

## Issuers
Let's encrypt provides two APIs: **live** and **staging**. 

### Staging
*Staging* is meant for testing the controller or making sure you can try it out without the fear or exhausting your rate limits while trying it out and it will provide you with certificates signed by Let's Encrypt staging CA, making the certs **not trusted**!

### Live
*Live* will provide you with trusted certificates signed by Let's Encrypt CA but has lower rate limits. This is what you want when you're done testing/evaluating the controller

## Deployment types

### Cluster wide
This deployment will provide certificate management for all namespaces in your cluster. You need elevated (admin) privileges to deploy it.

If you have this repository checked out, deploy it like: 

#### Staging
```bash
oc create -fdeploy/letsencrypt-live/cluster-wide/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-staging}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```

If you want to deploy it directly from GitHub use:

```bash
oc create -fhttps://raw.githubusercontent.com/tnozicka/openshift-acme/master/deploy/letsencrypt-live/cluster-wide/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-staging}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```

#### Live
```bash
oc create -fdeploy/letsencrypt-live/cluster-wide/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-live}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```

If you want to deploy it directly from GitHub use:

```bash
oc create -fhttps://raw.githubusercontent.com/tnozicka/openshift-acme/master/deploy/letsencrypt-live/cluster-wide/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-live}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```


### Specific namespaces
This deployment will provide certificate management for the namespace it's deployed to and explicitly specified namespaces. You have to make sure to give the SA correct permissions but you don't have to be cluster-admin. It works fine with regular user privileges.


#### Staging
```bash
oc create -fdeploy/letsencrypt-live/specific-namespaces/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-staging}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```

If you want to deploy it directly from GitHub use:

```bash
oc create -fhttps://raw.githubusercontent.com/tnozicka/openshift-acme/master/deploy/letsencrypt-live/specific-namespaces/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-staging}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```

#### Live
```bash
oc create -fdeploy/letsencrypt-live/specific-namespaces/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-live}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```

If you want to deploy it directly from GitHub use:

```bash
oc create -fhttps://raw.githubusercontent.com/tnozicka/openshift-acme/master/deploy/letsencrypt-live/specific-namespaces/{clusterrole,serviceaccount,imagestream,deployment,issuer-letencrypt-live}.yaml
oc adm policy add-cluster-role-to-user openshift-acme -z openshift-acme
```
