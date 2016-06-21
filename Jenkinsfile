node {
   stage "Checkout"
   checkout scm

   stage "Build"
   sh "docker-compose build"
   sh "docker-compose run web buildout"

   stage "Test"
   sh "docker-compose run web bin/test"
   step $class: 'JUnitResultArchiver', testResults: 'nosetests.xml'
   publishHTML target: [reportDir: 'htmlcov', reportFiles: 'index.html', reportName: 'Coverage report']
}
