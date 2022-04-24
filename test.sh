#export VAR=

#-short to run tests not connecting to network
#-coverprofile testCoverage.out
rm -f log/* && go clean -testcache && go test $(go list ./... | grep -v /examples) "$@"
