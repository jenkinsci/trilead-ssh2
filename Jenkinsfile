pipeline {
    agent { label 'linux' }
    stages {
        stage('Checkout') {
            steps {
                script {
                    infra.checkout()
                }
            }
        }
        stage('Build') {
            steps {
                script {
                    m2repo = "${pwd tmp: true}/m2repo"
                    String jdk = "8"
                    List<String> mavenOptions = [
                            '--update-snapshots',
                            "-Dmaven.repo.local=$m2repo",
                            '-Dmaven.test.failure.ignore',
                            "-Dfindbugs.failOnError=false",
                            "-Dset.changelist",
                            "-Djava.security.egd=file:/dev/./urandom",
                            "clean install",
                            "findbugs:findbugs"
                    ]

                    infra.runMaven(mavenOptions, jdk)
                }
             }
             post {
                 always {
                    /*
                     archiveArtifacts(allowEmptyArchive: true,
                         artifacts: "** /target/trilead*.jar",
                         onlyIfSuccessful: false)
                     */
                     junit(allowEmptyResults: true,
                         keepLongStdio: true,
                         testResults: "**/target/surefire-reports/**/*.xml")
                     script {
                        // MINSTALL-126 would make this easier by letting us publish to a different directory to begin with:
                        String m2repo = sh script: 'mvn -Dset.changelist -Dexpression=settings.localRepository -q -DforceStdout help:evaluate', returnStdout: true
                        // No easy way to load both of these in one command: https://stackoverflow.com/q/23521889/12916
                        String version = sh script: 'mvn -Dset.changelist -Dexpression=project.version -q -DforceStdout help:evaluate', returnStdout: true
                        echo "Collecting $version from $m2repo for possible Incrementals publishing"
                        dir(m2repo) {
                            archiveArtifacts "org/jenkins-ci/trilead-ssh2/$version/*$version*"
                        }
                        infra.maybePublishIncrementals()
                     }
                 }
             }
        }
    }
}
