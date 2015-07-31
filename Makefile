.PHONEY: binary

SRCDIR=calico_mesos
BUILD_FILES=build_calico_mesos
PYCALICO=$(wildcard build_calico_mesos/libcalico/*.py)
CALICO_MESOS=$(wildcard $(SRCDIR)/calico_mesos.py)
ST_TO_RUN?=calico_mesos/tests/st/

binary: dist/calico_mesos

# Create the image that builds calico_mesos
calico_mesos_builder.created: $(BUILD_FILES) $(PYCALICO)
	cd build_calico_mesos; docker build -t calico-mesos-builder .
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
	calico-mesos-builder pyinstaller calico_mesos/calico_mesos.py -a -F -s --clean

st: dist/calico_mesos
	nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer

run-etcd:
	@-docker rm -f mesos-etcd
	docker run --detach \
	--net=host \
	--name mesos-etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"
