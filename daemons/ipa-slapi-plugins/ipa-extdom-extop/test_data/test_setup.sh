export LD_PRELOAD=$(pkg-config --libs nss_wrapper)
export NSS_WRAPPER_PASSWD=./test_data/passwd
export NSS_WRAPPER_GROUP=./test_data/group
