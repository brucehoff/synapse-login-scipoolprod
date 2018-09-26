

```
export OAUTH_CLIENT_ID=...
export OAUTH_CLIENT_SECRET=...
docker build -t oauth-user-info --build-arg OAUTH_CLIENT_ID=foo --build-arg OAUTH_CLIENT_SECRET=bar .
docker run --rm -p 8080:8080 --name oauth-user-info oauth-user-info
```
