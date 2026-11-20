pipeline {
    agent { label 'linux' }
    stages {
        stage('Checkout') {
            steps {
                script {
                    infra.checkoutSCM()
                }
            }
        }
        stage('Build') {
            steps {
                script {
                    String jdk = "21"
                    List<String> mavenOptions = [
                            '--update-snapshots',
                            '-Dmaven.test.failure.ignore',
                            "-Dset.changelist",
                            "-Djava.security.egd=file:/dev/./urandom",
                            "clean install"
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
                        archiveArtifacts artifacts: 'target/trilead-ssh2*', fingerprint: true
                        infra.maybePublishIncrementals()
                     }
                 }
             }
        }
    }
}
