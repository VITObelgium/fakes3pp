# testing setup

In order to allow more extensive testing we run basic implementations of S3 servers as part of testing and
allow using them as part of the tests. For simplicity there are not separate hostnames so they do run on
localhost but they get distinguished by port number.

The downside of this is that we make assumptions on the development environment. This directory should help
developers setup their local environment to have the S3 servers running.

## Overview

From code it might be harder to understand what we are trying to simulate. But we are just trying to simulate
S3 servers which corresponds to different regions and thus 2 separate S3 stacks. These regions do not share any state.

In every region we create a bucket "backenddetails" that contains a file region.txt with the region name.

Currently we bootstrap the following regions:
 - tst-1 : available on port 5000
 - eu-test-2 : available on port 5001`


## Dependencies


### Dependencies bootstrap
Assumed dependencies are to have a modern Python3 runtime which supports virtual environments and pip.
By executing `make setup-test-dependencies` the required packages get downloaded and installed in the virtual
environment.

### Dependencies runtimes
In order to run the S3 servers and have them populated with the test files run `make start-test-s3-servers`
