# generate for amd64
GOOS=linux GOARCH=amd64 go build -o binary_amd64
seccomp-profiler ./binary_amd64 > seccomp_profile_amd64.go
rm binary_amd64
# generate for i386
#GOOS=linux GOARCH=386 go build -o binary_386
#seccomp-profiler ./binary_386 > seccomp_profile_i386.go
#rm binary_386