#!/usr/bin/env groovy

def FARM_LIST_CREDS = [
    'local' : 'e4bdd290-949c-43fd-ac6e-a992eff97b78',
    'abc' : 'abc1',
    ]
pipeline {
  parameters {
      string defaultValue: '', description: 'Jenkins farm name.', name: 'J_FARM_NAME', trim: true
      string defaultValue: '', description: 'Folder name (to be created).', name: 'J_FOLDER_NAME', trim: true
      string defaultValue: '', description: 'User(s) to grant access (CSV)', name: 'J_USER_LIST', trim: true
      string defaultValue: '', description: 'Permission(s) list (CSV)', name: 'J_PERMISSION_LIST', trim: true
    }
  agent any
  stages {
    stage('select farm creds') {
      steps{
        script {
          selectedFarmCred = FARM_LIST_CREDS["$J_FARM_NAME"]
          }
      }
    }
    stage('validate creds') {
      when {
        expression { return !selectedFarmCred }
      }
      steps {
        error("Unable to find api token for selected farm.")
      }
    }
    stage('create folder') {
      steps{
        withCredentials([usernamePassword(
                    credentialsId: selectedFarmCred,
                    passwordVariable: 'JENKINS_API_TOKEN',
                    usernameVariable: 'JENKINS_API_USER')]) {
          script {
            result = run_shell_script()
            echo result
          }
        }
      }
    }
    stage('validate result') {
      when {
        expression { return !(result =~ /Success: Folder created./) }
      }
      steps {
        error("Creating folder failed...")
      }
    }
  }
}

def run_shell_script() {
    shTxt = """
    #!/usr/bin/env bash
    python3 -m pip install --upgrade pipenv
    pipenv install
    pipenv run python createFolder.py \
     --farm $J_FARM_NAME \
     --folder $params.J_FOLDER_NAME \
     --user $params.J_USER_LIST \
     --permission $params.J_PERMISSION_LIST
     """
    result = sh (script: shTxt, returnStdout: true)
    return result
}
