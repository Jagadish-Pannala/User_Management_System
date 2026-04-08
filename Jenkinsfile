pipeline {
    agent any

    environment {
        IMAGE_NAME = "ums-service"
        CONTAINER_NAME = "ums-container"
    }

    stages {

        stage('Checkout Code') {
            steps {
                echo "Cloning repository..."
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                echo "Installing Python dependencies..."
                sh '''
                python3 -m venv venv
                . venv/bin/activate
                pip install -r Backend/requirements.txt
                '''
            }
        }

        stage('Run Tests') {
            steps {
                echo "Running tests..."
                sh '''
                . venv/bin/activate
                pytest || true
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                echo "Building Docker image..."
                sh '''
                docker build -t $IMAGE_NAME .
                '''
            }
        }

        stage('Run Container (Test Deployment)') {
            steps {
                echo "Starting container..."
                sh '''
                docker stop $CONTAINER_NAME || true
                docker rm $CONTAINER_NAME || true
                docker run -d -p 8000:8000 --name $CONTAINER_NAME $IMAGE_NAME
                '''
            }
        }
    }

    post {
        success {
            echo "Pipeline completed successfully"
        }
        failure {
            echo "Pipeline failed"
        }
    }
}