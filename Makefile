.PHONY: help check check-all check-zk verify package-check pq-toolchain pq-device
help:
	@echo 'make check           PQ Go tests, PQ evidence audit, 17 audit controls, runner checks'
	@echo 'make check-all       Go tests in all three modules, PQ and classical evidence audits'
	@echo 'make check-zk ZK_VERIFY=/absolute/path/to/zkverify  Reverify the 52 ZK rows'
	@echo 'make pq-toolchain    Download and build the pinned emulator and C bridge'
	@echo 'make pq-device       Test the built emulator; no existing lab needed'
	@echo 'make package-check   Check source completeness, links, file guide and secret patterns'
	@echo 'make verify          Check publication file hashes'
check:
	python3 scripts/check.py
check-all:
	python3 scripts/check.py --component all
check-zk:
	@test -n "$(ZK_VERIFY)" || (echo 'Set ZK_VERIFY to the built zkverify executable'; exit 2)
	python3 scripts/check.py --component zk --evidence-only --zk-verifier "$(ZK_VERIFY)"
pq-toolchain:
	cd pq-identity && scripts/build_pq_toolchain.sh
pq-device:
	cd pq-identity && A2AID_PQ_DEVICE=1 go test -race -count=1 -v -run TestDevice ./internal/pqdev
package-check:
	python3 docs/packaging/check_package.py
	python3 docs/packaging/test_package.py
verify:
	python3 docs/packaging/verify_manifest.py
