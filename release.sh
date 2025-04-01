
#!/usr/bin/env bash

go build -o demp

LATEST_TAG=$(./demp github latest-tag rianfowler/demp)
echo latest version: $LATEST_TAG

# NEW_VERSION=$(demp semver increment $LATEST_TAG patch)-rc
NEW_VERSION=$LATEST_TAG
echo new tag: $NEW_VERSION

# demp github new-release $NEW_VERSION main

./demp go-release $NEW_VERSION