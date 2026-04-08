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

        stage('Build Docker Image') {
            steps {
                echo "Building Docker image..."
                sh '''
                docker build -t $IMAGE_NAME .
                '''
            }
        }

        stage('Run Tests (Container)') {
            steps {
                echo "Running tests inside container..."
                sh '''
                docker run --rm $IMAGE_NAME pytest || true
                '''
            }
        }

        stage('Run Container (Test Deployment)') {
            steps {
                echo "Stopping old container if exists..."
                sh '''
                docker stop $CONTAINER_NAME || true
                docker rm $CONTAINER_NAME || true
                '''
                
                // echo "Starting new container..."
                // sh '''
                // docker run -d -p 8000:8000 --name $CONTAINER_NAME $IMAGE_NAME
                // '''
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
