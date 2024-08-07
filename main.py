from datetime import datetime, timedelta, timezone

import jwt
from fastapi import FastAPI, Request, status
from fastapi.responses import FileResponse, RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth

app = FastAPI()

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 240

# path to saml folder containing settings and cert files
# to generate certs run:
# openssl req -x509 -newkey rsa:2048 -keyout sp.key -out sp.crt -days 3650 --nodes
SAML_PATH = "./saml"


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def prepare_from_fastapi_request(request: Request, debug=False):
    form_data = await request.form()
    # use X-Forwarded-Proto header, fallback to request.url.scheme
    forwarded_proto = (
        request.headers.get("X-Forwarded-Proto", "").strip() or request.url.scheme
    )
    rv = {
        "https": "on" if forwarded_proto == "https" else "off",
        "http_host": request.url.hostname,
        "server_port": request.url.port,
        "script_name": request.url.path,
        "get_data": request.query_params,
        "post_data": {},
        # Advanced request options
        # "request_uri": "",
        # "query_string": "",
        # "validate_signature_from_qs": False,
        # "lowercase_urlencoding": False
    }
    if "SAMLResponse" in form_data:
        SAMLResponse = form_data["SAMLResponse"]
        rv["post_data"]["SAMLResponse"] = SAMLResponse
    if "RelayState" in form_data:
        RelayState = form_data["RelayState"]
        rv["post_data"]["RelayState"] = RelayState
    return rv


@app.get("/api/sso/saml/metadata")
async def saml_metadata(request: Request):
    req = await prepare_from_fastapi_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    saml_settings = auth.get_settings()
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if len(errors) != 0:
        print("Error found on Metadata: %s" % (", ".join(errors)))
        return errors
    with open("/tmp/sp-metadata.xml", "w") as file:
        file.write(str(metadata))
    return FileResponse(
        "/tmp/sp-metadata.xml", media_type="application/xml", filename="sp-metadata.xml"
    )


@app.get("/api/sso/saml/login")
async def saml_login(request: Request):
    req = await prepare_from_fastapi_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    callback_url = auth.login()
    return callback_url


@app.post("/api/sso/saml/callback")
async def saml_login_callback(request: Request):
    req = await prepare_from_fastapi_request(request, True)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    auth.process_response()
    errors = auth.get_errors()

    if len(errors) != 0:
        print(
            "Error when processing SAML Response: %s %s"
            % (", ".join(errors), auth.get_last_error_reason())
        )
        return "Error in callback"
    if not auth.is_authenticated():
        return "Not authenticated"

    attrs = auth.get_attributes()
    print(attrs)

    access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    access_token = create_access_token(
        data={"sub": attrs}, expires_delta=access_token_expires
    )
    return RedirectResponse(
        "/#/?token=" + access_token, status_code=status.HTTP_302_FOUND
    )
