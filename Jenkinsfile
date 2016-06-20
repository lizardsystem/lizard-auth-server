node {
   stage "Checkout"
   checkout scm

   stage "Build"
   sh "docker-compose -f docker-compose.yml build"
   sh "docker-compose -f docker-compose.yml run web buildout"
   sh "pwd"
   sh "ls -l eggs"

   stage "Test"
   sh "docker-compose -f docker-compose.yml run web bin/test"
   step $class: 'JUnitResultArchiver', testResults: 'nosetests.xml'
   publishHTML target: [reportDir: 'htmlcov', reportFiles: 'index.html', reportName: 'Coverage report']
}
