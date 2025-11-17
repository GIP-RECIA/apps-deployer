export PROJECT_HOME=/opt/${USER}/app-properties/prod/
export LOG_DIR=/home/${USER}/logs
export PUBLISHER_NUM=publisherX
export LANG=fr_FR.UTF-8

CATALINA_HOME=/opt/${USER}/tomcat
CATALINA_BASE=/opt/${USER}/tomcat
CATALINA_TMPDIR=$CATALINA_BASE/temp
CATALINA_PID=/opt/${USER}/tomcat/tomcat.pid

CATALINA_OPTS="$CATALINA_OPTS -server -XX:+UseG1GC -XX:+PrintFlagsFinal"
CATALINA_OPTS="$CATALINA_OPTS -Xms2G -Xmx6G"
CATALINA_OPTS="$CATALINA_OPTS -Djava.net.preferIPv4Stack=true -Dnetworkaddress.cache.ttl=3600"
CATALINA_OPTS="$CATALINA_OPTS -Djava.awt.headless=true -Dcom.sun.management.jmxremote -Dhttps.protocols=TLSv1.2,TLSv1.3"
CATALINA_OPTS="$CATALINA_OPTS -Dhttp.agent=Java-Publisher"
CATALINA_OPTS="$CATALINA_OPTS -Dserver.webapps=/opt/${USER}/webapps -Dserver.home=/opt/${USER}/tomcat"
CATALINA_OPTS="$CATALINA_OPTS -Dfile.encoding=UTF-8"
CATALINA_OPTS="$CATALINA_OPTS -Dspring.profiles.active=prod"

# Display settings at startup
CATALINA_OPTS="$CATALINA_OPTS -XX:+PrintCommandLineFlags"

# Prevent "Unrecognized Name" SSL warning
CATALINA_OPTS="$CATALINA_OPTS -Djsse.enableSNIExtension=true"

# Activating JMX
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.port=7777 -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false"

# We need to send a 'project.home' system property to the JVM;  use the value of PROJECT_HOME, if
# present, or fall back to a value calculated from $CATALINA_BASE

# [ -z "$PROJECT_HOME" ] && PROJECT_HOME="$CATALINA_BASE/PROJECT"
echo "PROJECT_HOME=$PROJECT_HOME"
# CATALINA_OPTS="$CATALINA_OPTS -Dproject.home=$PROJECT_HOME"

# Checking if anyother garbage collectors have been defined. If no other garbage
# collector is present, default to G1GC
# List of options taken from:
# http://www.oracle.com/webfolder/technetwork/tutorials/obe/java/gc01/index.html
echo $CATALINA_OPTS | grep -e '-XX:+UseSerialGC' -e '-XX:+UseParallelGC' -e '-XX:ParallelGCThreads' -e '-XX:+UseParallelOldGC' -e '-XX:+UseConcMarkSweepGC' -e '-XX:+UseParNewGC' -e '-XX:+CMSParallelRemarkEnabled' -e '-XX:CMSInitiatingOccupancyFraction' -e '-XX:+UseCMSInitiatingOccupancyOnly' -e '-XX:+UseG1GC'
if [ $? -eq 1 ]
then
    CATALINA_OPTS="$CATALINA_OPTS -XX:+UseG1GC"
fi

# Check to see if heap space allocation has been set
# If there are already set values, leave them be
echo $CATALINA_OPTS | grep -e '-Xms'
if [ $? -eq 1 ]
then
    CATALINA_OPTS="$CATALINA_OPTS -Xms1G"
fi

echo $CATALINA_OPTS | grep -e '-Xmx'
if [ $? -eq 1 ]
then
    CATALINA_OPTS="$CATALINA_OPTS -Xmx4G"
fi