{{/* KeyOf-safe slug: lowercase, spaces to dashes */}}
{{- define "blueprinter.slug" -}}
{{- . | lower | replace " " "-" -}}
{{- end -}}

{{/* Env var prefix for an OIDC app */}}
{{- define "blueprinter.envPrefix" -}}
{{- .envPrefix | default (printf "%s_OIDC" (upper (replace "-" "_" .name))) -}}
{{- end -}}

{{/* forwardauth.yaml — providers, applications and outpost in one ordered blueprint */}}
{{- define "blueprinter.forwardauth" -}}
version: 1
metadata:
  name: forwardauth-apps
entries:
{{- range .Values.forwardAuth.apps }}
  - model: authentik_providers_proxy.proxyprovider
    state: present
    id: {{ .name }}-provider
    identifiers:
      name: {{ .name }}-provider
    attrs:
      mode: forward_single
      external_host: {{ .host | default (printf "https://%s.%s" .name $.Values.domain) }}
      authorization_flow: !Find [authentik_flows.flow, [slug, {{ $.Values.authentik.authorizationFlow }}]]
      invalidation_flow: !Find [authentik_flows.flow, [slug, {{ $.Values.authentik.invalidationFlow }}]]
  - model: authentik_core.application
    state: present
    id: {{ .name }}-app
    identifiers:
      slug: {{ .name }}
    attrs:
      name: {{ .name }}
      provider: !KeyOf {{ .name }}-provider
{{- end }}
  - model: authentik_outposts.outpost
    state: present
    identifiers:
      managed: {{ .Values.forwardAuth.outpost }}
    attrs:
      providers:
{{- range .Values.forwardAuth.apps }}
        - !KeyOf {{ .name }}-provider
{{- end }}
{{- include "blueprinter.access" (dict "apps" .Values.forwardAuth.apps "access" .Values.access) }}
{{- end -}}

{{/* oidc.yaml — oauth2 providers and applications */}}
{{- define "blueprinter.oidc" -}}
version: 1
metadata:
  name: oidc-apps
entries:
{{- range .Values.oidcApps }}
{{- $prefix := include "blueprinter.envPrefix" . }}
  - model: authentik_providers_oauth2.oauth2provider
    state: present
    id: {{ .name }}-provider
    identifiers:
      name: {{ .name }}-provider
    attrs:
      client_type: confidential
      grant_types: # model default is [] which rejects every grant
        - authorization_code
        - refresh_token
      client_id: !Env {{ $prefix }}_CLIENT_ID
      client_secret: !Env {{ $prefix }}_CLIENT_SECRET
      authorization_flow: !Find [authentik_flows.flow, [slug, {{ $.Values.authentik.authorizationFlow }}]]
      invalidation_flow: !Find [authentik_flows.flow, [slug, {{ $.Values.authentik.invalidationFlow }}]]
      signing_key: !Find [authentik_crypto.certificatekeypair, [name, {{ $.Values.authentik.signingKey }}]]
      property_mappings:
{{- range (.scopes | default $.Values.authentik.defaultScopes) }}
        - !Find [authentik_providers_oauth2.scopemapping, [scope_name, {{ . }}]]
{{- end }}
      redirect_uris:
{{- range .redirectUris }}
        - matching_mode: strict
          url: {{ . }}
{{- end }}
  - model: authentik_core.application
    state: present
    id: {{ .name }}-app
    identifiers:
      slug: {{ .name }}
    attrs:
      name: {{ .name }}
      provider: !KeyOf {{ .name }}-provider
{{- end }}
{{- include "blueprinter.access" (dict "apps" .Values.oidcApps "access" .Values.access) }}
{{- end -}}

{{/* Per-application access control. Authentik allows every authenticated user
     when an application has no policy bindings, and superusers get NO bypass in
     the policy engine (PolicyBinding.passes is a plain membership check) — so
     deny-by-default means binding groups to every application, admin group
     included. Engine mode "any": one passing binding grants access. */}}
{{- define "blueprinter.access" -}}
{{- $access := .access | default dict -}}
{{- if $access.enabled }}
{{- $groups := dict -}}
{{- range .apps }}{{- range (.groups | default list) }}{{- $_ := set $groups . true }}{{- end }}{{- end }}
{{- range $g := (keys $groups | sortAlpha) }}
  - model: authentik_core.group
    state: present
    id: access-group-{{ include "blueprinter.slug" $g }}
    identifiers:
      name: {{ $g }}
{{- end }}
{{- range $app := .apps }}
{{- if $access.adminGroup }}
  - model: authentik_policies.policybinding
    state: present
    identifiers:
      target: !KeyOf {{ $app.name }}-app
      group: !Find [authentik_core.group, [name, {{ $access.adminGroup }}]]
    attrs:
      order: 0
      enabled: true
{{- end }}
{{- range $idx, $g := ($app.groups | default list) }}
  - model: authentik_policies.policybinding
    state: present
    identifiers:
      target: !KeyOf {{ $app.name }}-app
      group: !KeyOf access-group-{{ include "blueprinter.slug" $g }}
    attrs:
      order: {{ add 10 $idx }}
      enabled: true
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* rbac.yaml — roles, groups, users */}}
{{- define "blueprinter.rbac" -}}
version: 1
metadata:
  name: roles-groups-users
entries:
{{- range .Values.rbac.roles }}
  - model: authentik_rbac.role
    state: present
    id: role-{{ include "blueprinter.slug" . }}
    identifiers:
      name: {{ . }}
{{- end }}
{{- range .Values.rbac.groups }}
  - model: authentik_core.group
    state: present
    id: group-{{ include "blueprinter.slug" .name }}
    identifiers:
      name: {{ .name }}
{{- if or .superuser .roles }}
    attrs:
{{- if .superuser }}
      is_superuser: true
{{- end }}
{{- if .roles }}
      roles:
{{- range .roles }}
        - !KeyOf role-{{ include "blueprinter.slug" . }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- range .Values.rbac.users }}
  - model: authentik_core.user
    state: present
    identifiers:
      username: {{ .username }}
    attrs:
      name: {{ .name | default .username }}
{{- if .email }}
      email: {{ .email }}
{{- end }}
{{- if .passwordEnv }}
      password: !Env {{ .passwordEnv }}
{{- end }}
{{- if .groups }}
      groups:
{{- range .groups }}
        - !KeyOf group-{{ include "blueprinter.slug" . }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}
