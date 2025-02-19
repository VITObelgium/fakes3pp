BENCH_COUNT ?= 10


build-container:
	podman build -t fakes3pp -f Dockerfile .

run-container-s3:
	podman run --rm -v ./etc.private:/etc/fakes3pp:Z -p 8443:8443 -p 5555:5555 --env HOME=${HOME} -it localhost/fakes3pp:latest proxys3 --dot-env /etc/fakes3pp/.env.docker

run-container-sts:
	podman run --rm -v ./etc.private:/etc/fakes3pp:Z -p 8444:8444 -p 5555:5556 --env HOME=${HOME} -it localhost/fakes3pp:latest proxysts --dot-env /etc/fakes3pp/.env.docker

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

bench-dependencies:
	@test -s $(GOPATH)/bin/benchstat || go install golang.org/x/perf/cmd/benchstat@latest

bench-main: bench-dependencies
	git remote -v
	git fetch origin
	git rev-parse --short HEAD 2>/dev/null | tr -d '\n' | tee cmd/bench-current_ref.txt
	git branch -d "before_going_to_main" || echo "If there was no branch before_going_to_main then this is ok"
	git checkout -b "before_going_to_main"
	git checkout origin/main
	test -e cmd/bench-main.txt || (cd cmd && go test -bench=. -benchtime=5s -run "FakeS3Proxy" -benchmem -count=$(BENCH_COUNT) | tee bench-main.txt && cd ..)
	git checkout "before_going_to_main"

bench-current: bench-dependencies
	cd cmd && go test -bench=. -benchtime=5s -run "FakeS3Proxy" -benchmem -count=$(BENCH_COUNT) | tee bench-$(shell git rev-parse --short HEAD 2>/dev/null).txt && cd ..

bench-report: bench-dependencies
	benchstat cmd/bench-main.txt cmd/bench-$(shell git rev-parse --short HEAD 2>/dev/null).txt | tee cmd/bench-$(shell git rev-parse --short HEAD 2>/dev/null)-master-report.txt