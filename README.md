spaceservergo
=============

This is a Go implementation of a Space Server - an end-to-end encrypted, blockchain storage platform.

Build
=====

    go build

Install
=======

To allow binding to ports 80 and 443

    sudo setcap CAP_NET_BIND_SERVICE=+eip ./spaceservergo
