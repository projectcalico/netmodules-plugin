.PHONY: binary
BUILD_DIR=build_calico_mesos
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt
CALICO_MESOS_FILES=calico_mesos/calico_mesos.py

default: help
calico_mesos: dist/calico_mesos  ## Create the calico_mesos plugin binary

## Create the calico_mesos plugin binary
dist/calico_mesos: $(CALICO_MESOS_FILES)
	mkdir -p -m 777 dist/

	# Build the mesos plugin
	docker run --rm \
         -v `pwd`/calico_mesos/:/code/calico_mesos \
         -v `pwd`/dist/:/code/dist \
				 calico/build:v0.12.0 \
	 pyinstaller calico_mesos/calico_mesos.py -ayF

## Run the UTs in a container
ut:
	# Use the `root` user, since code coverage requires the /code directory to
	# be writable.  It may not be writable for the `user` account inside the
	# container.
	docker run --rm -v `pwd`/calico_mesos:/code -u root \
	calico/test \
	nosetests tests/unit -c nose.cfg

ut-circle: calico_mesos
	docker run \
	-v `pwd`/calico_mesos:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
        calico/test sh -c \
	'nosetests tests/unit  -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

## Clean everything (including stray volumes)
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist

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
