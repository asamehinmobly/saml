from flask import Flask
from lazyView import LazyView


def create_app():
    _app = Flask('saml')
    _app.config['SECRET_KEY'] = 'onelogindemopytoolkit'

    _app.add_url_rule("/users-notification/sso/<string:owner_id>/<string:provider>", methods=['GET', 'POST'],
                      view_func=LazyView('auth.saml_login', False))

    _app.add_url_rule("/users-notification/sso/<string:owner_id>/<string:provider>/metadata", methods=['GET'],
                      view_func=LazyView('auth.metadata', False))

    return _app


app = create_app()

if __name__ == "__main__":
    app.run(host='0.0.0.0')
