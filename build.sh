#!/bin/bash
#
# Copyright 2019 Aletheia Ware LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -x

go fmt $GOPATH/src/aletheiaware.com/{aliasgo,aliasservergo,bcclientgo,bcgo,bcnetgo,bcservergo,financego,spaceclientgo,spacego,spaceservergo}
go test $GOPATH/src/aletheiaware.com/{aliasgo,aliasservergo,bcclientgo,bcgo,bcnetgo,bcservergo,financego,spaceclientgo,spacego,spaceservergo}
env GOOS=linux GOARCH=amd64 go build -o $GOPATH/bin/spaceservergo-linux-amd64 aletheiaware.com/spaceservergo

(cd $GOPATH/src/aletheiaware.com/spaceservergo/ && zip -r html.zip html)
