# Agent Environment Probe Prompt

Run `./agent_env_probe.sh` exactly as provided and return the complete stdout verbatim.

Do not modify the probe or perform any actions outside it. The bounded actions performed by the probe itself—including temporary writes/downloads/package execution, loopback socket and GCC checks, unprivileged namespace/rootless-runtime inspection, and the guarded `apt` install/purge of `hello`—are authorized. If anything is blocked or unavailable, report the probe result as-is and do not try to bypass the restriction.
