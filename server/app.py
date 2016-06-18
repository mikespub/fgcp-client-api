#!/usr/bin/env python3

import connexion

if __name__ == '__main__':
    app = connexion.App(__name__, specification_dir='./swagger/')
    app.add_api('swagger.yaml', arguments={'title': 'Demo REST API for the Fujitsu Cloud IaaS Trusted Public S5 (TPS5) aka Fujitsu Global Cloud Platform (FGCP) - generated from SwaggerHub'})
    app.run(port=8080)
