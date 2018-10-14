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
                            "clean install",
                            "findbugs:findbugs"
                    ]

                    infra.runMaven(mavenOptions, jdk)
                }
             }
             post {
                 always {
                     archiveArtifacts(allowEmptyArchive: true,
                         artifacts: "**/target/*.jar",
                         onlyIfSuccessful: false)
                     junit(allowEmptyResults: true,
                         keepLongStdio: true,
                         testResults: "**/target/surefire-reports/**/*.xml")
                 }
             }
        }
    }
}