FROM guligo/jdk-maven-ant-tomcat
COPY . /
RUN mvn package
# move the .war file into the webapp directory of your Tomcat
RUN mv /target/oauthUserInfo-1.0.war /etc/tomcat-8.0.24/webapps
COPY etc/server.xml /etc/tomcat-8.0.24/conf/

