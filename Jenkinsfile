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
                    m2repo = "${pwd tmp: true}/m2repo"
                    String jdk = "21"
                    List<String> mavenOptions = [
                            '--update-snapshots',
                            "-Dmaven.repo.local=$m2repo",
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
                        archiveArtifacts artifacts: 'target/trilead-ssh2*.jar', fingerprint: true
                        infra.maybePublishIncrementals()
                     }
                 }
             }
        }
    }
}
