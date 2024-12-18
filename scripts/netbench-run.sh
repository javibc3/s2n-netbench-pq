#!/usr/bin/env bash
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# immediately exit if an error occurs.
set -e

ARTIFACT_FOLDER="target/release"
NETBENCH_ARTIFACT_FOLDER="target/s2n-netbench"

# remove the old results if the folder contains anything
if [ "$(ls -A $NETBENCH_ARTIFACT_FOLDER)" ]; then
    rm -rf $NETBENCH_ARTIFACT_FOLDER/*
fi

# the run_trial function will run the request-response scenario
# with the driver passed in as the first argument
run_trial() {
    # e.g. request-response
    SCENARIO=$1
    # e.g. s2n-quic
    DRIVER=$2
    echo "running the $SCENARIO scenario with $DRIVER"

    # make a directory to hold the collected statistics
    mkdir -p $NETBENCH_ARTIFACT_FOLDER/results/$SCENARIO/$DRIVER

    # run the server while collecting metrics.
    echo "  running the server"
    sudo ./$ARTIFACT_FOLDER/s2n-netbench-collector \
    ./$ARTIFACT_FOLDER/s2n-netbench-driver-server-$DRIVER \
    --scenario ./$NETBENCH_ARTIFACT_FOLDER/$SCENARIO.json \
    > $NETBENCH_ARTIFACT_FOLDER/results/$SCENARIO/$DRIVER/server.json &
    # store the server process PID. $! is the most recently spawned child pid
    SERVER_PID=$!

    # sleep for a small amount of time to allow the server to startup before the
    # client
    sleep 1

    # run the client. Port 4433 is the default for the server.
    echo "  running the client"
    sudo SERVER_0=localhost:4433 ./$ARTIFACT_FOLDER/s2n-netbench-collector \
     ./$ARTIFACT_FOLDER/s2n-netbench-driver-client-$DRIVER \
     --scenario ./$NETBENCH_ARTIFACT_FOLDER/$SCENARIO.json \
     > $NETBENCH_ARTIFACT_FOLDER/results/$SCENARIO/$DRIVER/client.json

    # cleanup server processes. The collector PID (which is the parent) is stored in
    # SERVER_PID. The collector forks the driver process. The following incantation
    # kills the child processes as well.
    echo "  killing the server"
    kill $(ps -o pid= --ppid $SERVER_PID)
}

# build all tools in the netbench workspace
# cargo build --profile=bench

# generate the scenario files. This will generate .json files that can be found
# in the netbench/target/netbench directory. Config for all scenarios is done
# through this binary.
# This environment variable is used to set the signature algorithm for the scenarios. 
# It supports all the post-quantum algorithms as specified in https://github.com/open-quantum-safe/oqs-provider.
SIGNATURE_ALGORITHM="mldsa44"
./$ARTIFACT_FOLDER/s2n-netbench-scenarios --request_response.connections 10000 --request_response.request_size 1 --request_response.response_size 1

# run_trial request_response s2n-quic
# run_trial request_response s2n-tls
run_trial request_response openssl
run_trial request_response openssl-mlkem768

# run_trial connect s2n-quic
# run_trial connect s2n-tls
run_trial connect openssl
run_trial connect openssl-mlkem768


echo "generating the report"
./$ARTIFACT_FOLDER/s2n-netbench report-tree $NETBENCH_ARTIFACT_FOLDER/results $NETBENCH_ARTIFACT_FOLDER/report