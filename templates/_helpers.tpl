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
    # state: created writes once and never updates, so a seeded password is not
    # re-applied over one the user has since changed.
    state: {{ .state | default "present" }}
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

{{/* firstlogin.yaml — force username/email/password change on first login.

     Gated on a user attribute this flow sets itself, never one seeded by the
     blueprint: a seeded attribute is re-enforced on every apply, so the prompt
     would come back forever. Attribute absent == setup not done.

     Bound into the authentication flow after MFA (order 30) and before the
     login stage (order 100), so the user is authenticated but not yet signed
     in. Stage bindings default to re_evaluate_policies=true, and
     ReevaluateMarker builds the policy engine with PLAN_CONTEXT_PENDING_USER,
     so the policy sees the user logging in rather than an anonymous request. */}}
{{- define "blueprinter.firstlogin" -}}
{{- $fl := .Values.firstLogin -}}
{{- $attr := $fl.attribute | default "setup_complete" -}}
{{- $order := int ($fl.order | default 50) -}}
{{- $flow := $fl.flow | default "default-authentication-flow" -}}
version: 1
metadata:
  name: first-login-setup
entries:
  - model: authentik_stages_prompt.prompt
    state: present
    id: fl-username
    identifiers:
      name: first-login-username
    attrs:
      field_key: username
      label: Username
      type: username
      required: true
      order: 10
      initial_value: return user.username
      initial_value_expression: true
      sub_text: Keep the name you were given or choose your own.
  - model: authentik_stages_prompt.prompt
    state: present
    id: fl-email
    identifiers:
      name: first-login-email
    attrs:
      field_key: email
      label: Email
      type: email
      required: true
      order: 20
      initial_value: return user.email
      initial_value_expression: true
  # Exactly two password-type fields in one stage are auto-validated to match.
  - model: authentik_stages_prompt.prompt
    state: present
    id: fl-password
    identifiers:
      name: first-login-password
    attrs:
      field_key: password
      label: New password
      type: password
      required: true
      order: 30
  - model: authentik_stages_prompt.prompt
    state: present
    id: fl-password-repeat
    identifiers:
      name: first-login-password-repeat
    attrs:
      field_key: password_repeat
      label: Repeat password
      type: password
      required: true
      order: 31
  # user_write maps attributes.<key> onto the user's attributes — this is what
  # stops the prompt reappearing on the next login.
  - model: authentik_stages_prompt.prompt
    state: present
    id: fl-done
    identifiers:
      name: first-login-done-marker
    attrs:
      field_key: attributes.{{ $attr }}
      label: Setup complete
      type: hidden
      required: false
      order: 90
      initial_value: "true"

  - model: authentik_stages_prompt.promptstage
    state: present
    id: fl-prompt-stage
    identifiers:
      name: first-login-prompt
    attrs:
      fields:
        - !KeyOf fl-username
        - !KeyOf fl-email
        - !KeyOf fl-password
        - !KeyOf fl-password-repeat
        - !KeyOf fl-done

  - model: authentik_stages_user_write.userwritestage
    state: present
    id: fl-write-stage
    identifiers:
      name: first-login-write
    attrs:
      user_creation_mode: never_create

  - model: authentik_policies_expression.expressionpolicy
    state: present
    id: fl-policy
    identifiers:
      name: first-login-required
    attrs:
      expression: |
        pending = request.user
        if not pending or not pending.is_authenticated:
            return False
        if pending.username in {{ $fl.excludeUsers | default list | toJson }}:
            return False
        return not pending.attributes.get("{{ $attr }}", False)

  - model: authentik_flows.flowstagebinding
    state: present
    id: fl-prompt-binding
    identifiers:
      target: !Find [authentik_flows.flow, [slug, {{ $flow }}]]
      stage: !KeyOf fl-prompt-stage
      order: {{ $order }}
    attrs:
      evaluate_on_plan: false
      re_evaluate_policies: true
  - model: authentik_flows.flowstagebinding
    state: present
    id: fl-write-binding
    identifiers:
      target: !Find [authentik_flows.flow, [slug, {{ $flow }}]]
      stage: !KeyOf fl-write-stage
      order: {{ add $order 1 }}
    attrs:
      evaluate_on_plan: false
      re_evaluate_policies: true

  - model: authentik_policies.policybinding
    state: present
    identifiers:
      target: !KeyOf fl-prompt-binding
      policy: !KeyOf fl-policy
    attrs:
      order: 0
      enabled: true
  - model: authentik_policies.policybinding
    state: present
    identifiers:
      target: !KeyOf fl-write-binding
      policy: !KeyOf fl-policy
    attrs:
      order: 0
      enabled: true
{{- end -}}
