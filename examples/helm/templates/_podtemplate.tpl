{{/*
Reusable pod template — referenced by both the Job and the CronJob in job.yaml.
*/}}
{{- define "jso-protector.podTemplate" -}}
metadata:
  labels:
    {{- include "jso-protector.labels" . | nindent 4 }}
spec:
  restartPolicy: Never
  initContainers:
    - name: checkout
      image: {{ .Values.images.git | quote }}
      env:
        - name: REPO_URL
          value: {{ .Values.repo.url | quote }}
        - name: REPO_REF
          value: {{ .Values.repo.ref | quote }}
      command:
        - sh
        - -c
        - |
          set -eu
          cd /workspace
          git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" .
          echo "Checked out $(git rev-parse HEAD)"
      volumeMounts:
        - name: workspace
          mountPath: /workspace
  containers:
    - name: protect
      image: {{ .Values.images.node | quote }}
      workingDir: /workspace
      envFrom:
        - secretRef:
            name: {{ include "jso-protector.secretName" . }}
      command:
        - sh
        - -c
        - |
          set -eu
          cd /workspace
          SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

          npm ci --no-audit --no-fund
          npm run build
          npx jso-protector --config {{ .Values.protect.configPath }} --release-check --json
          npx jso-protector --config {{ .Values.protect.configPath }} --competitor-gap-report --json
          npx jso-protector \
            --config {{ .Values.protect.configPath }} \
            --preset {{ .Values.protect.preset }} \
            --label "$SHA" \
            --manifest {{ .Values.protect.manifestPath }} \
            --report   {{ .Values.protect.reportPath }}

          ls -la "$(dirname {{ .Values.protect.manifestPath }})"
      volumeMounts:
        - name: workspace
          mountPath: /workspace
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
  volumes:
    - name: workspace
      emptyDir: {}
{{- end }}
