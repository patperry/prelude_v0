
    local> docker pull ubuntu:bionic
    local> docker run -v /Users/ptrck/Projects/prelude:/root/prelude \
               --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
               -it ubuntu:bionic bash
    docker> apt-get update
    docker> apt-get -y install gcc gdb netbase

