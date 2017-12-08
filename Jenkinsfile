node {
   stage "Checkout"
   checkout scm

   stage "Build"
   sh "echo 'COMPOSE_PROJECT_NAME=${env.JOB_NAME}-${env.BUILD_ID}' > .env"
   sh "docker-compose down --volumes"
   sh "docker-compose build"
   sh "docker-compose run web buildout"

   stage "Test"
   sh "docker-compose run web bin/test"
   sh "docker-compose down --volumes"
   step $class: 'JUnitResultArchiver', testResults: 'nosetests.xml'
   publishHTML target: [reportDir: 'htmlcov', reportFiles: 'index.html', reportName: 'Coverage report']
}
