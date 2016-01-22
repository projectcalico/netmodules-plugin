.PHONY: binary
BUILD_DIR=build_calico_mesos
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt
CALICO_MESOS_FILES=calico_mesos/calico_mesos.py

default: help
calico_mesos: dist/binary/calico_mesos  ## Create the calico_mesos plugin binary
build_image: build_calico_mesos/.calico_mesos_builder.created ## Create the calico/mesos-build image
docker_image: dockerized-mesos/.dockerized_mesos.created ## Create the calico/mesos-calico image
docker_image.tar: dist/docker/mesos-calico.tar ## Create the calico/mesos-calico image, and tar it.

## Create the image that builds calico_mesos.
build_calico_mesos/.calico_mesos_builder.created: $(BUILD_DIR)
	cd build_calico_mesos && docker build -t calico/mesos-builder .
	touch build_calico_mesos/.calico_mesos_builder.created

## Create the calico_mesos plugin binary
dist/binary/calico_mesos: $(CALICO_MESOS_FILES) build_image
	mkdir -p -m 777 dist/binary/

	# Build the mesos plugin
	-docker run --rm \
	 -v `pwd`/calico_mesos:/code/calico_mesos \
	 -v `pwd`/dist/binary:/code/dist \
	 calico/mesos-builder \
	 pyinstaller calico_mesos/calico_mesos.py -ayF

## Run etcd in a container
run-etcd:
	@-docker rm -f mesos-etcd
	docker run --detach \
	--net=host \
	--name mesos-etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

# TODO: maybe change this so docker runs and handles the caching itself,
# instead of relying on the .created file.
dockerized-mesos/.dockerized_mesos.created: calico_mesos
	docker build -f ./Dockerfile -t calico/mesos-calico .
	touch dockerized-mesos/.mesos_calico_image.created

# Tar up the calico/mesos-calico docker image
dist/docker/mesos-calico.tar: docker_image
	mkdir -p dist/docker
	docker save -o dist/docker/mesos-calico.tar calico/mesos-calico

jenkins: calico_mesos
	docker build -t calico/mesos-calico .

jenkins-vagrant: calico_mesos docker_image.tar
	vagrant up


## Run the UTs in a container
ut: build_calico_mesos/.calico_mesos_builder.created
	# Use the `root` user, since code coverage requires the /code directory to
	# be writable.  It may not be writable for the `user` account inside the
	# container.
	docker run --rm -v `pwd`/calico_mesos:/code -u root \
	calico/mesos-builder bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	nosetests tests/unit -c nose.cfg'

ut-circle: calico_mesos rpm
	docker run \
	-v `pwd`/calico_mesos:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
        calico/mesos-builder bash -c \
        '/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	cd calico_containers; nosetests tests/unit  -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

## Create the calico-mesos RPM
rpm: calico_mesos
	mkdir -p -m 777 dist/rpm/
	docker build -t calico/mesos-rpm-builder ./packages
	docker run \
	-v `pwd`/dist/binary/:/binary/ \
	-v `pwd`/dist/rpm/:/root/rpmbuild/RPMS/ \
	calico/mesos-rpm-builder

## Clean everything (including stray volumes)
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-rm -f mesos-calico.tar
	-docker rmi calico/mesos-calico
	-docker rmi calico/mesos-builder
	-docker rmi calico/mesos-rpm-builder

help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	$(info Available targets)
	@awk '/^[a-zA-Z\-\_0-9]+:/ {                                   \
		nb = sub( /^## /, "", helpMsg );                             \
		if(nb == 0) {                                                \
			helpMsg = $$0;                                             \
			nb = sub( /^[^:]*:.* ## /, "", helpMsg );                  \
		}                                                            \
		if (nb)                                                      \
			printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg; \
	}                                                              \
	{ helpMsg = $$0 }'                                             \
	width=$$(grep -o '^[a-zA-Z_0-9]\+:' $(MAKEFILE_LIST) | wc -L)  \
	$(MAKEFILE_LIST)
