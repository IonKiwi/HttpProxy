{
    "ServerBindings": [{
            "port": 80,
            "config": null
        }
    ],
    "Proxy": [{
            "path": "/test1",
            "target": "https://52.157.226.194/",
            "newHttpClient": false,
            "headers": [{
                    "key": "X-Proxied-By",
                    "value": "http_proxy"
                }, {
                    "key": "Host",
                    "value": "ionkiwi.nl"
                }
            ],
            "removeHeaders": [
                "Accept-Encoding"
            ]
        }, {
            "path": "/test2",
            "target": "https://ionkiwi.nl/"
        }
    ]
}
