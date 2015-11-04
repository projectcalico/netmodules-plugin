.PHONEY: binary

SRCDIR=calico_mesos
BUILD_DIR=build_calico_mesos
PYCALICO=$(wildcard $(BUILD_DIR)/libcalico/calico_containers/pycalico/*.py)
CALICO_MESOS=$(wildcard $(SRCDIR)/calico_mesos.py)

binary: dist/calico_mesos

# Create the image that builds calico_mesos
calico_mesos_builder.created: $(BUILD_DIR) $(PYCALICO)
	cd build_calico_mesos; docker build -t calico/mesos-builder .
	touch calico_mesos_builder.created

# Create the binary: check code changes to source code, ensure builder is created.
dist/calico_mesos: $(CALICO_MESOS) calico_mesos_builder.created
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the mesos plugin
	docker run \
	-u user \
	-v `pwd`/calico_mesos:/code/calico_mesos \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_mesos \
	calico/mesos-builder pyinstaller calico_mesos/calico_mesos.py -a -F -s --clean

run-etcd:
	@-docker rm -f mesos-etcd
	docker run --detach \
	--net=host \
	--name mesos-etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

mesos_calico_image.created:
	docker build -f ./Dockerfile -t calico/mesos-calico .
	touch mesos_calico_image.created

mesos-calico.tar: mesos_calico_image.created
	docker save --output mesos-calico.tar calico/mesos-calico

ut: calico_mesos_builder.created
	# Use the `root` user, since code coverage requires the /code directory to
	# be writable.  It may not be writable for the `user` account inside the
	# container.
	docker run --rm -v `pwd`/calico_mesos:/code -u root \
	calico/mesos-builder bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	nosetests tests/unit  -c nose.cfg'

ut-circle: calico_mesos_builder.created dist/calico_mesos
	docker run \
	-v `pwd`/calico_mesos:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
        calico/mesos-builder bash -c \
        '/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	cd calico_containers; nosetests tests/unit  -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-rm -f mesos-calico.tar
	-docker rmi calico/mesos-calico
	-docker rmi calico/mesos-builder
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes
