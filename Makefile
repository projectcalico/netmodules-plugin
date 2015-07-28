.PHONEY: binary

binary: dist/calico

dist/calico:
	# Build docker container
	cd build_calico_mesos; docker build -t calico-mesos-build .
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the mesos plugin
	docker run \
	-u user \
	-v `pwd`/calico_mesos:/code/calico_mesos \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_mesos \
	calico-mesos-build pyinstaller calico_mesos/calico_mesos.py -a -F -s --clean
