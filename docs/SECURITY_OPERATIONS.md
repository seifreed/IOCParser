# Security And Operations

## Secrets

- inject queue and database credentials through secrets
- do not commit real credentials to the repository

## TLS

- prefer TLS-enabled broker endpoints
- mount CA bundles and client certs via secret volumes

## IAM / permissions

- scope worker identities to the exact queues and databases they need
- keep release jobs and runtime identities separate

## Rotation

- rotate queue/database secrets independently of application releases
- restart workers after rotation if the client cannot reload credentials dynamically

## Alerts

- alert on dead-letter growth
- alert on queue lag
- alert on repeated retryable failures
