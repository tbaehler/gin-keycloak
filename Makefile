TESTTIMEOUT := 30s
tests: ## Run all the tests
	echo 'mode: atomic' > coverage.txt && go test -covermode=atomic -coverprofile=coverage.txt -race -timeout=$(TESTTIMEOUT) ./...

test:  ## Run one test
	go test -v -timeout=$(TESTTIMEOUT) ./... -run '^$(TESTNAME)$$'