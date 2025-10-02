// BRS-GPT: Jenkins Pipeline
// Company: EasyProTech LLC (www.easypro.tech)
// Dev: Brabus
// Date: 2025-09-16 00:30:00 UTC
// Status: Modified
// Telegram: https://t.me/easyprotech

pipeline {
    agent any

    environment {
        REGISTRY = 'ghcr.io'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    def repoUrl = scm.getUserRemoteConfigs()[0].getUrl().replaceAll(/\.git$/, '')
                    def parts = repoUrl.tokenize('/')
                    def repoName = parts[-1]
                    def repoOwner = parts[-2]
                    env.IMAGE_NAME = "${repoOwner}/${repoName}"
                    env.DOCKER_IMAGE = "${env.REGISTRY}/${env.IMAGE_NAME}:${env.BUILD_NUMBER}"
                    env.DOCKER_IMAGE_LATEST = "${env.REGISTRY}/${env.IMAGE_NAME}:latest"
                }
            }
        }

        stage('Test') {
            steps {
                script {
                    docker.image('python:3.10').inside {
                        sh '''
                            set -e
                            python -m pip install --upgrade pip
                            pip install -r requirements.txt
                            if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi
                            pip install -e .
                            python -m pytest tests/ -v --tb=short --cov=brsgpt --cov-report=xml --junitxml=test-results.xml
                        '''
                    }
                }
            }
            post {
                always {
                    junit 'test-results.xml'
                    cobertura coberturaReportFile: 'coverage.xml', onlyStable: false
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    docker.build(env.DOCKER_IMAGE, '.')
                    env.DOCKER_IMAGE_BUILT = 'true'
                }
            }
        }

        stage('Security Scan') {
            when {
                expression { return env.DOCKER_IMAGE_BUILT == 'true' }
            }
            steps {
                script {
                    sh """
                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -v ${env.WORKSPACE}:/workspace \
                            aquasec/trivy:latest image --format json --output /workspace/trivy-results.json ${env.DOCKER_IMAGE}
                    """
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-results.json', fingerprint: true, onlyIfSuccessful: false
                }
            }
        }

        stage('Push Docker Image') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                }
            }
            steps {
                script {
                    docker.withRegistry("https://${env.REGISTRY}", 'ghcr-credentials') {
                        docker.image(env.DOCKER_IMAGE).push()
                        docker.image(env.DOCKER_IMAGE).push('latest')
                    }
                }
            }
        }

        stage('Deploy to Staging') {
            when {
                branch 'develop'
                expression { return env.OPENAI_API_KEY?.trim() }
            }
            steps {
                script {
                    withEnv(["OPENAI_API_KEY=${env.OPENAI_API_KEY}"]) {
                        sh '''
                            docker run -d --rm --name brs-gpt-staging \
                                -e OPENAI_API_KEY=${OPENAI_API_KEY} \
                                ${DOCKER_IMAGE_LATEST} \
                                start example.com --profile lightning --model gpt-4o-mini
                        '''
                    }
                }
            }
        }

        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                script {
                    sh '''
                        aws ecs update-service \
                            --cluster brs-gpt-cluster \
                            --service brs-gpt-service \
                            --task-definition ${TASK_DEFINITION_ARN} \
                            --force-new-deployment
                    '''
                }
            }
        }

        stage('Performance Test') {
            when {
                expression { return env.OPENAI_API_KEY?.trim() }
            }
            steps {
                script {
                    withEnv(["OPENAI_API_KEY=${env.OPENAI_API_KEY}"]) {
                        docker.image(env.DOCKER_IMAGE).inside {
                            sh '''
                                set -e
                                time brs-gpt start testphp.vulnweb.com --profile lightning --model gpt-4o-mini
                            '''
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            sh 'docker system prune -f'
            cleanWs()
        }
        success {
            script {
                if (env.BRANCH_NAME == 'main') {
                    echo "BRS-GPT deployment successful"
                }
            }
        }
        failure {
            script {
                echo "BRS-GPT deployment failed"
            }
        }
    }
}
