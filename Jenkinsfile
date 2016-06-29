node {
   stage "Checkout"
   checkout scm

   stage "Build"
   sh "docker-compose build"
   sh "docker-compose run web python3 bootstrap.py"
   sh "docker-compose run web bin/buildout"

   stage "Test"
   sh "docker-compose run web bin/coverage run bin/test"
   sh "docker-compose run web bin/coverage report"
   sh "docker-compose run web bin/test html"
   sh "docker-compose run web bin/test xml"
   step $class: 'JUnitResultArchiver', testResults: 'nosetests.xml'
   publishHTML target: [reportDir: 'htmlcov', reportFiles: 'index.html', reportName: 'Coverage report']
}
