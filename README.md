# OpenSAML 5 and Quarkus

This is a simple project to demonstrate the use of OpenSAML 5 and Quarkus that demonstrates how to
log in a user using SAML together with Quarkus security.


OpenSAML5 is jakarta based and works very well with Quarkus WebServlet annotation.


* Login endpoint is http://localhost:8080/SAML2/login
* Assert endpoint is http://localhost:8080/SAML2/assert
* Open endpoint is http://localhost:8080/countries/open
* Protected endpoint http://localhost:8080/countries/closed

## Running the application in dev mode

You can run your application in dev mode using:
```shell script
./mvnw compile quarkus:dev
```
