# royal_blobs_jwt_service

<h3>HS512 JWT in Rust, service to service JWT references/templates.</h3>

This program is meant to be updated before any real use.

There are hard coded HMAC and identity values in the template.

The service runs locally within a backend, providing JWT + BLAKE2 of JWT + blob back to the caller, logging UUID and BLAKE2 of JWT in the service.

This service is not meant to provide security by itself, but instead is to be used within a backend API.

<h2>Adding a little something to JWTs, maybe a blob and hash, maybe some client auth TLS, maybe some alerting</h2>

The default JWT TTL is 60 seconds. 

By default, nothing is done with the RSA signed blob other than be provided to approved sources.

The blob is 384 bytes while in base64 mode. If you don't need the blob, it can removed. But the idea is to include a blob that can be used for short term disposable shared secrets at the data level, between the client and the service as additional layers around the JWT in the header for example. Validation functions not included, other than the example HS512 JWT validation.

The default returned data structure is in this format, JWT, then a pipe character:, then a random RSA blob. 

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIyIiwicm9sZSI6IkFkbWluIiwiZXhwIjoxNjQ5MzA5ODAyfQ.ltmDMT_GiZ69pGQ6DBkVllf7yECrWyerox6Zg8tUv35G4ls_49ljrYPw5xZPEWSfp7q14KFA8glGP95GNffhUQ|cC5uxYEH9/+NSsAz4ut43BC6rUqWAZ9ILwJgZuk1rkdA7BsoMWFRMkrXwKgV0vJXXo1uM39+rBgdYU8xmGWlu1ZERhnWJ/+EMjDPqWU7dgexr2nStwnvNXNFcb9VU+baLFhOJAyVMLF9L7dduyCzKfxukikAhCP7NLtCYdGFUTaSAtSmRL9yGlouetWSyxfyqdyExsOy3wwk7j6pdRbJbyTAF4z7VV7P+nTWCpZzMAMJLbKpM1DlK9rsMFQFm/zK3UVB0QIslbKwz2Z6I0/deiNqh6d9fnHBMxm1hbUVHignnmu9dodUwmxi36wPoSBo2QGHqACK7UzmOpYkTEvDig==
```

Here is an example of the server default logging:

```
2022-04-07 05:35:42.747162389 UTC - royal_blobs_jwt_service INFO - START JWT usage UID b259153c-b0bc-41c4-a8b1-31c5db68f909
2022-04-07 05:35:42.747326288 UTC - royal_blobs_jwt_service INFO - b259153c-b0bc-41c4-a8b1-31c5db68f909 - base64 BLAKE2: "YZSHXCb4KDspH+n93wQzTnqx7Q6E8Wp6RPMv0NQOUQD41xdrg04pqzDFN45VMsjyg4kS7smmRiWJmehsnLDVMA=="
2022-04-07 05:39:04.604539899 UTC - royal_blobs_jwt_service ERRO - error: Rejection(NotFound)
2022-04-07 05:42:54.933738557 UTC - royal_blobs_jwt_service INFO - START JWT usage UID 5b0dda78-ff11-41ba-bfbc-f5103bbd8044
2022-04-07 05:42:54.933975968 UTC - royal_blobs_jwt_service INFO - 5b0dda78-ff11-41ba-bfbc-f5103bbd8044 - base64 BLAKE2: "ok8ap5leL7SavJS+QEiiEePvHzSvtQir+UMdT/x+h6kcA33+amg5VlsSYS9MydOQ+BYBb5XWQquWFFqCT1welQ=="
2022-04-07 05:42:55.504966785 UTC - royal_blobs_jwt_service INFO - admin resource provided
2022-04-07 05:42:55.539278618 UTC - royal_blobs_jwt_service INFO - START JWT usage UID 9f2ec22b-0a11-4548-a0b6-510801ba4de2
2022-04-07 05:42:55.539366355 UTC - royal_blobs_jwt_service INFO - 9f2ec22b-0a11-4548-a0b6-510801ba4de2 - base64 BLAKE2: "QPIPueQANrr0iZwtMlYzuiKCcyHcmtKfI4s3BxWR7GAYJ1NldeJIyh3D4GivA2aI8Dypyk8Qy/YbYckP4yjYOg=="
2022-04-07 05:42:55.796527861 UTC - royal_blobs_jwt_service INFO - admin resource provided
```

Converting between a base64 BLAKE2 and a hex BLAKE2 manually:

```
# echo -n QPIPueQANrr0iZwtMlYzuiKCcyHcmtKfI4s3BxWR7GAYJ1NldeJIyh3D4GivA2aI8Dypyk8Qy/YbYckP4yjYOg== | base64 -d | xxd -p | tr -d '\n'
40f20fb9e40036baf4899c2d325633ba22827321dc9ad29f238b37071591ec601827536575e248ca1dc3e068af036688f03ca9ca4f10cbf61b61c90fe328d83a
```

<h2>Ephemeral Design</h2>

There is no storage other than the server log by default. Within the server logging we have UUID v4 for each token request that is paired with a BLAKE2 hash of the JWT and timestamps. HTTP client errors are logged on the server side, TCP-only clients like telnet will not be logged or responded to unless they send in HTTP formatted data etc.

The client may chose to store the data as it wishes but likely does not need to keep anything for more than 60 seconds, unless the JWT TTL is adjusted, or the blobs are put to some other use. The blobs could be used as an approved entropy source, encryption password/keyfiles, or other layers.

<h4>structure of the response</h4>

```HS512 JWT | BLOB```

