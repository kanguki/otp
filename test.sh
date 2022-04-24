#export VAR=

#-short to run tests not connecting to network
#-coverprofile testCoverage.out

# if keys files are absent, add it
ls | grep keys && ls cipher/ | grep keys
if [[ $? -ne 0 ]]; then
 ./cipher/gen_rsa.sh && `cd cipher && ./gen_rsa.sh` 
fi
rm -f log/* && go clean -testcache && go test $(go list ./... | grep -v /examples) "$@"
