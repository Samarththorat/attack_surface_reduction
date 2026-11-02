from asrms.routes.api import api
from asrms.routes.pages import pages
from asrms.routes.reports import reports


def register_routes(app):
    app.register_blueprint(pages)
    app.register_blueprint(api, url_prefix="/api")
    app.register_blueprint(reports, url_prefix="/api/reports")
