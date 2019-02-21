spaceservergo
=============

This is a Go implementation of a Space Server - end-to-end encrypted, blockchain-backed, data storage.

Build
=====

    go build

Install
=======

To allow binding to ports 80 and 443

    sudo setcap CAP_NET_BIND_SERVICE=+eip ./spaceservergo
