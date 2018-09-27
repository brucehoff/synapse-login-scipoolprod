This app shows what is returned by the Google Identity API:
```
https://www.googleapis.com/oauth2/v2/userinfo
```

It is configured to be run as a Google AppEngine application.  To deploy:
- create an OAuth client
- enter the client ID and secret in `src/main/resources/global.properties`
- customize Auth.getRedirectBackUrl() as needed
- run `mvn appengine:deploy`
