# K8S deployment

## Whitelists

If you are not using the whitelist, you must modify the deployment by:

 1. Removing the `--whitelist` option from the args.
 1. Omitting the whitelist.json from the config filesystem.


## Recommended Configuration


If you are using the whitelist, the whitelist.json to include the principals you want to whitelist:

```
kubectl create configmap auth-proxy-whitelist --from-file=whitelist=whitelist.json
```

and verify:

```
kubectl get configmap auth-proxy-whitelist -o yaml
```

NOTE: The whitelist is stored separately from the configuration as it is optional.

You need three values for the basic configuration:

 1. The OAuth client id.
 1. The OAuth client secret.
 1. The endpoint that is being proxied (typically the dns name of the internal service).

With this values, create the configuration

```
kubectl create secret generic auth-proxy-secret --from-literal=client-id='...' --from-literal=client-secret='...' --from-literal=session-key='...'
kubectl create configmap auth-proxy-config --from-literal=endpoint='http://myservice.mynamespace.svc.cluster.local:8888/'
```

where the client id, secret, and endpoint are substituted as necessary.

Then verify:

```
kubectl get secret auth-proxy-secret -o yaml
kubectl get configmap auth-proxy-config -o yaml
```

## Deploy Redis

The sessions can be shared by using redist. The current deployment configuration relies on Redis.

```
kubectl create configmap redis-config --from-file=redis.conf
```

Deploy redis via:
```
kubectl apply -f redis-deployment.yaml
```

Once the pod has deployed, you can verify that you can connect to the master via:
```
kubectl exec -it $(kubectl get po -o name | grep redis-master | cut -d / -f 2) redis-cli
```

## Deployment

The deployment is a simple flask application. If you intend to scale the proxy,
you will need to added session sharing the flask application configuration.

```
kubectl apply -f deployment.yaml
```
