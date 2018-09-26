FROM guligo/jdk-maven-ant-tomcat
COPY . /
RUN mvn package
# move the .war file into the webapp directory of your Tomcat
RUN mv /target/oauthUserInfo-1.0.war /etc/tomcat-8.0.24/webapps
COPY etc/server.xml /etc/tomcat-8.0.24/conf/
ARG OAUTH_CLIENT_ID
ARG OAUTH_CLIENT_SECRET
RUN echo OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID} >> /etc/tomcat-8.0.24/conf/catalina.properties
RUN echo OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET} >> /etc/tomcat-8.0.24/conf/catalina.properties
