from werkzeug.utils import import_string, cached_property


class LazyView(object):

    def __init__(self, import_name, auth=True, auth_type="admin"):
        self.middle_wares = []
        self.__module__, self.__name__ = import_name.rsplit('.', 1)
        self.import_name = import_name
        self.auth = auth
        self.auth_type = auth_type

    @property
    def view_with_middleware(self):
        view = self.view
        for middle_ware in reversed(self.middle_wares):
            view = middle_ware(view, self.auth, self.auth_type)
        return view

    @cached_property
    def view(self):
        return import_string(self.import_name)

    def __call__(self, *args, **kwargs):
        # from flask import request
        response = self.view_with_middleware(*args, **kwargs)
        # if settings.LOG_LEVEL > 0:
        #     log_message = "request: {}\nresponse: {}".format(
        #         json.dumps(serialize_flask_request(request), indent=4, default=default_converter),
        #         json.dumps(serialize_flask_response(response), indent=4, default=default_converter))
        #     if response.status_code >= 400:
        #         app.logger.error(log_message)
        #     elif response.status_code < 400 and settings.LOG_LEVEL > 1:
        #         app.logger.info(log_message)
        return response
