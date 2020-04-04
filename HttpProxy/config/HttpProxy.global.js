{
    "ServerBindings": [{
            "port": 59638,
            "config": null
        }, {
            "port": 59639,
            "config": {
                "ServerCertificateProvider": "WindowsStore",
                "ServerCertificate": "CN=TLS localhost"
            }
        }
    ],
    "Proxy": [{
            "path": "/test1",
            "target": "https://52.157.226.194/",
            "newHttpClient": false,
            "overrideHost": "ionkiwi.nl",
            "headers": [{
                    "key": "X-Proxied-By",
                    "value": "http_proxy"
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
