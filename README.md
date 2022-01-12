# SAML
## For Run
* Run `pip3 install -r src/requirements.pip` to install python packages.
* Run the app (default port is 5000).
* Request `/users-notification/sso/9445de632d31f18cc95f1b5127ae8401225db4646a5cc6dc9274bb57274828ab/directv?sso` using `GET` method
* The previous endpoint will generate a URL to login in directv.
* Also, there are setting for SP and IDP in `setting.json` file and advanced setting for security in `advanced_settings.json` file.