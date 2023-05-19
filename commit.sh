#!/bin/bash

commit_changes() {
    docker commit $(my_ap) <my_app>
}

trap commit_changes EXIT

# Your additional commands and configurations inside the container

# Start the interactive shell
/bin/bash
