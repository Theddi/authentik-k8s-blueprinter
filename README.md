# Authentik Kubernetes Blueprinter
A Helm Chart to create a ConfigMap containing Blueprints for [Authentik on Kubernetes](https://docs.goauthentik.io/install-config/install/kubernetes/)

## Prerequisites
This chart was tested only with Traefik's GatewayAPI (Middleware in HTTPRoutes)

## Description
Instead of hand-writing one ConfigMap per blueprint, this chart renders a
single ConfigMap where every `.yaml` key is an authentik blueprint,
generated from compact values:

- **forwardAuth** — one proxy provider (`forward_single`) + application per
  app, and the embedded-outpost registration derived from the same list.
  Everything is emitted into ONE blueprint file, so entries apply in order
  and the outpost can never go out of sync with the providers.
- **oidcApps** — one oauth2 provider + application per app, credentials
  referenced via `!Env` from the authentik worker's environment.
- **rbac** — roles, groups (with role assignment / superuser flag) and
  users (optional managed password via `!Env`).
- **extraBlueprints** — verbatim passthrough for hand-written blueprints.

See [values.yaml](values.yaml) for examples.

## Usage with Argocd

1. Deploy the chart into the authentik namespace:

   ```yaml
   sources:
     - repoURL: https://github.com/Theddi/authentik-k8s-blueprinter.git
       targetRevision: HEAD
       path: .
       helm:
         valueFiles:
           - $values/<directories>/authentik-blueprints/values.yml
     - repoURL: <your-gitops-repo>
       targetRevision: HEAD
       ref: values
   ```

2. Mount the generated ConfigMap in the authentik chart values:

   ```yaml
   blueprints:
     configMaps:
       - authentik-blueprints
   ```

3. For OIDC apps and managed user passwords, expose the referenced env
   vars on the authentik worker (authentik chart values), e.g.:

   ```yaml
   global:
     env:
       - name: MYAPP_OIDC_CLIENT_ID
         valueFrom:
           secretKeyRef: { name: myapp-oidc, key: client_id }
       - name: MYAPP_OIDC_CLIENT_SECRET
         valueFrom:
           secretKeyRef: { name: myapp-oidc, key: client_secret }
   ```