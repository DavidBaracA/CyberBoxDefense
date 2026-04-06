# crAPI Template Assets

This directory contains the bundled local assets used by CyberBoxDefense to deploy OWASP crAPI through the predefined template flow.

Source reference:

- Official OWASP/crAPI repository
- `deploy/docker/docker-compose.yml`
- `deploy/docker/.env`

Local adjustments for the thesis MVP:

- removed fixed `container_name` declarations so multiple compose projects can coexist
- exposed only the primary web port and MailHog UI port
- parameterized those host ports through `CRAPI_PORT` and `CRAPI_MAILHOG_PORT`
- kept deployment local-first with `LISTEN_IP=127.0.0.1` by default

TODO:
- pin and review a specific crAPI image version for stronger reproducibility
- add post-deploy health probing before marking the target as healthy in the UI
- bundle any additional upstream assets if future crAPI releases require them
