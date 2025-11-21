pipeline {
    agent any

    // 기존 파이프라인의 환경 변수를 참고하여 Job에 맞게 재정의
    environment {
        // 1. Harbor 및 이미지 정보
        HARBOR_URL        = "shkch.duckdns.org"
        HARBOR_PROJECT    = "elf_analyzer" // Job 이미지에 맞게 프로젝트 이름 변경
        HARBOR_CREDS_ID   = "harbor-creds"
        JOB_IMAGE_NAME    = "elf-analyzer" // Job 이미지 이름
        
        // 2. K8s 접속 및 Job 정보
        KUBE_CREDS_ID     = "kubeconfig-creds"
        SSH_HOST          = "sangsu02.iptime.org"
        K8S_USER          = "server4"
        K8S_TARGET_IP     = "192.168.0.10" 
        K8S_PORT          = "6443"
        
        // Job 관련 파일 경로
        JOB_YAML_FILE     = 'analyzer-job.yaml' // Job YAML 파일 경로
        JOB_NAME          = 'elf-analyzer-job'
    }

    stages {
        // --- 1. Git Checkout ---
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        // --- 2. 이미지 태그 정의 (Git Commit SHA 사용) ---
        stage('Define Image Tag') {
            steps {
                script {
                    env.IMAGE_TAG = sh(returnStdout: true, script: 'git rev-parse --short=8 HEAD').trim()
                    echo "Using Image Tag: ${env.IMAGE_TAG}"
                }
            }
        }

        // --- 3. Job 이미지 빌드 및 푸시 ---
stage('Build & Push Job Image') {
    steps {
        // Harbor 인증
        withCredentials([usernamePassword(credentialsId: env.HARBOR_CREDS_ID, usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS')]) {
            sh "echo ${HARBOR_PASS} | docker login ${env.HARBOR_URL} -u ${HARBOR_USER} --password-stdin"
            
            // 문제 해결: 'script' 블록으로 변수 정의 및 사용을 감쌈
            script {
                def FULL_IMAGE = "${env.HARBOR_URL}/${env.HARBOR_PROJECT}/${env.JOB_IMAGE_NAME}:${env.IMAGE_TAG}"
                
                echo "Building Job Image: ${FULL_IMAGE}"
                
                // Dockerfile이 프로젝트 루트에 있다고 가정
                sh "docker build -t ${FULL_IMAGE} ."
                sh "docker push ${FULL_IMAGE}"
            }
        }
    }
}

        // --- 4. Kubernetes에 Job 배포 및 실행 ---
        stage('Deploy & Run Job') {
            steps {
                script {
                    def localPort = 8888 
                    def KUBECONFIG_PATH
                    def tunnelPid

                    // 1. SSH 터널 시작
                    sshagent(['k8s-master-ssh-key']) {
                        sh "nohup ssh -o StrictHostKeyChecking=no -N -L ${localPort}:${env.K8S_TARGET_IP}:${env.K8S_PORT} ${env.K8S_USER}@${env.SSH_HOST} > /dev/null 2>&1 & echo \$! > tunnel.pid"
                        
                        tunnelPid = readFile('tunnel.pid').trim()
                        sleep 10 // 터널 활성화 대기

                        // 2. Kubeconfig 수정 및 배포
                        withCredentials([file(credentialsId: env.KUBE_CREDS_ID, variable: 'KUBECONFIG_FILE')]) {
                            sh "sed -i 's|server:.*|server: https://127.0.0.1:${localPort}|g' ${KUBECONFIG_FILE} || true" 
                            KUBECONFIG_PATH = env.KUBECONFIG_FILE
                            
                            // 3. Job YAML 파일의 이미지 태그 업데이트 (sed 사용)
                            //  배포 전 Job YAML 파일 내부의 이미지 태그를 현재 SHA로 교체
                            sh "sed -i 's|image:.*${env.JOB_IMAGE_NAME}:latest|image: ${env.HARBOR_URL}/${env.HARBOR_PROJECT}/${env.JOB_IMAGE_NAME}:${env.IMAGE_TAG}|g' ${JOB_YAML_FILE}"
                            
                            echo "Deploying new Job with image tag: ${env.IMAGE_TAG}"

                            // 4. 기존 Job 삭제 (Job은 재실행을 위해 삭제 후 재배포가 필요)
                            sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl delete job ${env.JOB_NAME} --ignore-not-found=true" 

                            // 5. 새 Job 배포 및 실행
                            sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl apply -f ${JOB_YAML_FILE}" 
                            
                            // 6. Job 완료 대기 및 로그 출력 (최대 5분)
                            sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl wait --for=condition=complete job/${env.JOB_NAME} --timeout=300s"
                            
                            // 7. 완료된 Job의 로그 출력 (디버깅 목적)
                            sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl logs jobs/${env.JOB_NAME}"
                        }
                    }
                    
                    // 8. SSH 터널 종료
                    sh "kill ${tunnelPid} || true" 
                    sh "rm -f tunnel.pid || true"
                }
            }
        }
    }
    
    post {
        always {
            sh "docker logout ${env.HARBOR_URL} || true"
            // Job 이미지는 다음 빌드 캐시를 위해 유지하거나, 필요 시 삭제
        }
    }
}