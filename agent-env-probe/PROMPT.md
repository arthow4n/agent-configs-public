# Agent Environment Probe Prompt

Run `./agent_env_probe.sh` exactly as provided and return the complete stdout verbatim.

Do not modify the probe or perform any actions outside it. The bounded actions performed by the probe itself—including allowlisted environment and repository-layout metadata, temporary filesystem capability checks, downloads/package execution, loopback socket and development-server checks, no-body HTTPS checks to common development services, compiler/build checks, an offline Android/Gradle compile, a local-page headless-browser screenshot, a local-image-only container run, a temporary Git workflow, unprivileged namespace/rootless-runtime inspection, short CPU/ML/GPU capability and matrix-multiplication tests, and the guarded `apt` install/purge of `hello`—are authorized. If anything is blocked or unavailable, report the probe result as-is and do not try to bypass the restriction.
