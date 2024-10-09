build-container:
	podman build -t fakes3pp -f Dockerfile .

run-container-s3:
	podman run --rm -v ./etc.private:/etc/fakes3pp:Z -p 8443:8443 --env HOME=${HOME} -it localhost/fakes3pp:latest proxys3 --dot-env /etc/fakes3pp/.env.docker

run-container-sts:
	podman run --rm -v ./etc.private:/etc/fakes3pp:Z -p 8444:8444 --env HOME=${HOME} -it localhost/fakes3pp:latest proxysts --dot-env /etc/fakes3pp/.env.docker
