# Docs

Identity Service is the identity provider for your products. You register an
application here, users belong to that application, and this service issues
the tokens your APIs verify.

These pages explain the system in the order most people need it.

| Start here | What you will understand |
| --- | --- |
| [How it works](how-it-works.md) | The parties involved, how tenancy works, and how data moves through the service |
| [Create an application](create-an-app.md) | How auth starts: register an app, configure it, sign a user in |
| [OAuth lifecycle](oauth-lifecycle.md) | The redirect flow between your app, this service, and the hosted login UI |
| [Tokens](tokens.md) | What each token is for, what is inside it, and how other services verify it |
| [Reference](reference.md) | Endpoints, environment variables, errors, and Firestore collections |

The root [README](../README.md) covers local setup, configuration, and
running tests. Request schemas live in the generated OpenAPI UI at
`/docs` once the service is running.
