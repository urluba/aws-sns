#!/usr/bin/env python3

import connexion
import logging

logging.basicConfig( level=logging.DEBUG)

app = connexion.App( __name__, specification_dir='./swagger/')
app.add_api( 'swagger.yaml')

if __name__ == '__main__':
    app.run( port=5000 )

