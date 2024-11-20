build-container:
	podman build -t fakes3pp -f Dockerfile .

run-container-s3:
	podman run --rm -v ./etc.private:/etc/fakes3pp:Z -p 8443:8443 --env HOME=${HOME} -it localhost/fakes3pp:latest proxys3 --dot-env /etc/fakes3pp/.env.docker

run-container-sts:
	podman run --rm -v ./etc.private:/etc/fakes3pp:Z -p 8444:8444 --env HOME=${HOME} -it localhost/fakes3pp:latest proxysts --dot-env /etc/fakes3pp/.env.docker

setup-test-dependencies:
	[ ! -f testing/venv/moto ] && python3 -m venv testing/venv/moto
	./testing/venv/moto/bin/pip3 install -r testing/requirements.txt

start-test-s3-servers:
	./testing/venv/moto/bin/moto_server -p 5000 >testing/server_5000.log 2>testing/server_5000.err &
	./testing/venv/moto/bin/moto_server -p 5001 >testing/server_5001.log 2>testing/server_5001.err &
	./testing/venv/moto/bin/python3 testing/bootstrap_backend.py testing/backends/tst-1 http://localhost:5000
	./testing/venv/moto/bin/python3 testing/bootstrap_backend.py testing/backends/eu-test-2 http://localhost:5001

stop-test-s3-servers:
	for pid in `ps -ef | grep testing/venv/moto/bin/python3 | grep -v grep | awk '{print $$2}'`; do kill "$${pid}"; done
