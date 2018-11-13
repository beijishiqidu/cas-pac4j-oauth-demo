## What is this project?

This *cas-pac4j-oauth-demo* project has been created to test the authentication delegation in the CAS server.

## Build & test

Build the project:

```shell
cd cas-pac4j-oauth-demo
mvn clean package
```

And run the built WAR (`cas.war`) in Tomcat on `http://localhost:8080/cas`.

Use `jleleu`/`jleleu` or `leleuj`/`leleuj` to log in.

Authorized applications match the following pattern: `^http://localhost:.*`.

curl -v -k -X POST --header "Content-Type:text/xml;charset=UTF-8" --data @logout-request.soap "https://localhost:8080/cas/login?client_name=Shibboleth&logoutendpoint=true"
