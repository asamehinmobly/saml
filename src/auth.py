import os
from flask import (request, render_template, redirect, session, make_response)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), ''))
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'script_name': request.path,
        'get_data': request.args.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.form.copy()
    }


# @app.route('/', methods=['GET', 'POST'])
def saml_login(owner_id, provider):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    if auth:
        print("init saml auth success")
    else:
        print("failed to auth saml")
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if 'sso' in request.args:
        print("------- sso ----------")
        return auth.login()
        # If AuthNRequest ID need to be stored in order to later validate it, do instead
        # sso_built_url = auth.login()
        # request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return redirect(sso_built_url)
    elif 'sso2' in request.args:
        print("------------ sso2 ----------")
        return_to = '%sattrs/' % request.host_url
        return redirect(auth.login(return_to))
    elif 'slo' in request.args:
        print("----------------- slo ------------------")
        name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']
        if 'samlNameIdFormat' in session:
            name_id_format = session['samlNameIdFormat']
        if 'samlNameIdNameQualifier' in session:
            name_id_nq = session['samlNameIdNameQualifier']
        if 'samlNameIdSPNameQualifier' in session:
            name_id_spnq = session['samlNameIdSPNameQualifier']

        return redirect(auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq))
    elif 'acs' in request.args:
        print("------------- acs ---------------")
        request_id = None
        try:
            print("------------- start try ---------------")
            if 'AuthNRequestID' in session:
                request_id = session['AuthNRequestID']
            print("------------ process response -----------------------")
            print("request_id: {}".format(request_id))
            auth.process_response(request_id=request_id)
            errors = auth.get_errors()
            print("----------------- errors ----------------")
            print(errors)

            not_auth_warn = not auth.is_authenticated()
            print("------------- authenticated {} --------------------".format(not_auth_warn))
            if len(errors) == 0:
                if 'AuthNRequestID' in session:
                    del session['AuthNRequestID']
                session['samlUserdata'] = auth.get_attributes()
                session['samlNameId'] = auth.get_nameid()
                session['samlNameIdFormat'] = auth.get_nameid_format()
                session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
                session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
                session['samlSessionIndex'] = auth.get_session_index()
                print("---------------- session -----------------")
                print(session)
                self_url = OneLogin_Saml2_Utils.get_self_url(req)
                print("------------------ self_url {} -----------------".format(self_url))
                if 'RelayState' in request.form and self_url != request.form['RelayState']:
                    # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                    # the value of the request.form['RelayState'] is a trusted URL.
                    print("-------------- Relay state -------------------")
                    print(request.form['RelayState'])
                    template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Direct TV</title>
</head>
<body>
<script>
    window.location.href = '{base_url}/caracol/app/html/directtv/?token={token}'
</script>
</body>
</html>"""
                    template = template.replace("{base_url}", "http://demo.bolt-play.com")
                    template = template.replace("{token}", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MzgyNzk0OTcsImlhdCI6MTYzODE5MzA5NywibmJmIjoxNjM4MTkzMDk3LCJzdWIiOnsidXNlciI6eyJ1c2VybmFtZSI6ImNhcmFjb2wtZGV2IiwiYXBwX2lkIjoyMSwiZW1haWwiOiJjYXJhY29sLXN1cG9ydEBpbm1vYmx5LmNvbSIsImZpcnN0X25hbWUiOiJjYXJhY29sIiwiaWQiOjM3LCJsYXN0X25hbWUiOiIifSwiYXBwbGljYXRpb24iOnsiYXBwX2lkZW50aWZpZXIiOiIzMzFjNjg3MWQ0YzVhNmNkN2I4ZDRhYmRhMzQ5YTQ2NjRmOTcxY2VjZmZmMWQzNmNkNDU5OWYxNzZhZjA4OTE1IiwiaWQiOjIxLCJhcHBfbmFtZSI6IkNhcmFjb2wiLCJleHRlcm5hbF9rZXkiOiIiLCJhcHBfY29uZmlnIjp7Imxhbmd1YWdlIjp7ImRlZmF1bHQiOnsibmFtZSI6IlNwYW5pc2giLCJrZXkiOiJlcyJ9LCJsYW5ndWFnZXMiOlt7Im5hbWUiOiJFbmdsaXNoIiwia2V5IjoiZW4ifSx7Im5hbWUiOiJTcGFuaXNoIiwia2V5IjoiZXMifV19LCJkZWZhdWx0X3BsYW5zIjp7ImVuIjp7IjMwIjoiTW9udGhseSIsIjkwIjoiUXVhcnRlcmx5IiwiMzY1IjoiWWVhcmx5In0sImVzIjp7IjMwIjoiTW9udGhseSIsIjkwIjoiUXVhcnRlcmx5IiwiMzY1IjoiWWVhcmx5In19LCJleHBvcnRpbmdfa2V5cyI6bnVsbCwidXNlcl9tYW5hZ2VtZW50Ijp7ImluY2x1ZGVfZXh0ZXJuYWxzIjpudWxsfX19fX0.ZwNvS8gfdyKRQCw2q2EG1L_0sceBZUTWU45jQtDCVE0")
                    # return render_template('/index.html', base_url="http://demo.bolt-play.com", token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MzgyNzk0OTcsImlhdCI6MTYzODE5MzA5NywibmJmIjoxNjM4MTkzMDk3LCJzdWIiOnsidXNlciI6eyJ1c2VybmFtZSI6ImNhcmFjb2wtZGV2IiwiYXBwX2lkIjoyMSwiZW1haWwiOiJjYXJhY29sLXN1cG9ydEBpbm1vYmx5LmNvbSIsImZpcnN0X25hbWUiOiJjYXJhY29sIiwiaWQiOjM3LCJsYXN0X25hbWUiOiIifSwiYXBwbGljYXRpb24iOnsiYXBwX2lkZW50aWZpZXIiOiIzMzFjNjg3MWQ0YzVhNmNkN2I4ZDRhYmRhMzQ5YTQ2NjRmOTcxY2VjZmZmMWQzNmNkNDU5OWYxNzZhZjA4OTE1IiwiaWQiOjIxLCJhcHBfbmFtZSI6IkNhcmFjb2wiLCJleHRlcm5hbF9rZXkiOiIiLCJhcHBfY29uZmlnIjp7Imxhbmd1YWdlIjp7ImRlZmF1bHQiOnsibmFtZSI6IlNwYW5pc2giLCJrZXkiOiJlcyJ9LCJsYW5ndWFnZXMiOlt7Im5hbWUiOiJFbmdsaXNoIiwia2V5IjoiZW4ifSx7Im5hbWUiOiJTcGFuaXNoIiwia2V5IjoiZXMifV19LCJkZWZhdWx0X3BsYW5zIjp7ImVuIjp7IjMwIjoiTW9udGhseSIsIjkwIjoiUXVhcnRlcmx5IiwiMzY1IjoiWWVhcmx5In0sImVzIjp7IjMwIjoiTW9udGhseSIsIjkwIjoiUXVhcnRlcmx5IiwiMzY1IjoiWWVhcmx5In19LCJleHBvcnRpbmdfa2V5cyI6bnVsbCwidXNlcl9tYW5hZ2VtZW50Ijp7ImluY2x1ZGVfZXh0ZXJuYWxzIjpudWxsfX19fX0.ZwNvS8gfdyKRQCw2q2EG1L_0sceBZUTWU45jQtDCVE0")
                    return template
                    # return redirect(auth.redirect_to(request.form['RelayState']))
            elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()
                print(error_reason)
        except Exception as err:
            print(err.__repr__())
            return redirect("https://stagingott.bolt-play.com/", code=302)
    elif 'sls' in request.args:
        print("--------------- sls -------------")
        request_id = None
        if 'LogoutRequestID' in session:

            request_id = session['LogoutRequestID']
        dscb = lambda: session.clear()
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        print(errors)
        if len(errors) == 0:
            if url is not None:
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the url is a trusted URL.
                return redirect(url)
            else:
                success_slo = True
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
            print(error_reason)

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            print(session["samlUserdata"])
            attributes = session['samlUserdata'].items()

    return redirect("http://demo.bolt-play.com/caracol/app/html/directtv", code=302)

    # return render_template(
    #     'index.html',
    #     errors=errors,
    #     error_reason=error_reason,
    #     not_auth_warn=not_auth_warn,
    #     success_slo=success_slo,
    #     attributes=attributes,
    #     paint_logout=paint_logout
    # )


# @app.route('/attrs/')
def attrs():
    paint_logout = False
    attributes = False
    print("-------- /attrs/ ----------")
    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template('attrs.html', paint_logout=paint_logout, attributes=attributes)


# @app.route('/metadata/')
def metadata(owner_id, provider):
    print("request /metadata")
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    print(errors)
    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp


