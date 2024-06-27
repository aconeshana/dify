import json
import urllib.parse
from dataclasses import dataclass

import requests


@dataclass
class OAuthUserInfo:
    id: str
    name: str
    email: str


class OAuth:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self):
        raise NotImplementedError()

    def get_access_token(self, code: str):
        raise NotImplementedError()

    def get_raw_user_info(self, token: str):
        raise NotImplementedError()

    def get_user_info(self, token: str) -> OAuthUserInfo:
        raw_info = self.get_raw_user_info(token)
        return self._transform_user_info(raw_info)

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        raise NotImplementedError()


class GitHubOAuth(OAuth):
    _AUTH_URL = 'https://github.com/login/oauth/authorize'
    _TOKEN_URL = 'https://github.com/login/oauth/access_token'
    _USER_INFO_URL = 'https://api.github.com/user'
    _EMAIL_INFO_URL = 'https://api.github.com/user/emails'

    def get_authorization_url(self):
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'user:email'  # Request only basic user information
        }
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        headers = {'Accept': 'application/json'}
        response = requests.post(self._TOKEN_URL, data=data, headers=headers)

        response_json = response.json()
        access_token = response_json.get('access_token')

        if not access_token:
            raise ValueError(f"Error in GitHub OAuth: {response_json}")

        return access_token

    def get_raw_user_info(self, token: str):
        headers = {'Authorization': f"token {token}"}
        response = requests.get(self._USER_INFO_URL, headers=headers)
        response.raise_for_status()
        user_info = response.json()

        email_response = requests.get(self._EMAIL_INFO_URL, headers=headers)
        email_info = email_response.json()
        primary_email = next((email for email in email_info if email['primary'] == True), None)

        return {**user_info, 'email': primary_email['email']}

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        email = raw_info.get('email')
        if not email:
            email = f"{raw_info['id']}+{raw_info['login']}@users.noreply.github.com"
        return OAuthUserInfo(
            id=str(raw_info['id']),
            name=raw_info['name'],
            email=email
        )


class GoogleOAuth(OAuth):
    _AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
    _TOKEN_URL = 'https://oauth2.googleapis.com/token'
    _USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'

    def get_authorization_url(self):
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': 'openid email'
        }
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri
        }
        headers = {'Accept': 'application/json'}
        response = requests.post(self._TOKEN_URL, data=data, headers=headers)

        response_json = response.json()
        access_token = response_json.get('access_token')

        if not access_token:
            raise ValueError(f"Error in Google OAuth: {response_json}")

        return access_token

    def get_raw_user_info(self, token: str):
        headers = {'Authorization': f"Bearer {token}"}
        response = requests.get(self._USER_INFO_URL, headers=headers)
        response.raise_for_status()
        return response.json()

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(raw_info['sub']),
            name=None,
            email=raw_info['email']
        )


class DingtalkOAuth(OAuth):
    # https://open.dingtalk.com/document/orgapp/scan-qr-code-to-log-on-to-third-party-websites#title-z3q-ijy-dxz
    # _AUTH_URL = 'https://oapi.dingtalk.com/connect/oauth2/sns_authorize'
    # https://open.dingtalk.com/document/orgapp/tutorial-obtaining-user-personal-information#title-ts9-exq-xrh
    _AUTH_URL = 'https://login.dingtalk.com/oauth2/auth'
    _TOKEN_URL = 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken'
    _USER_INFO_URL = 'https://api.dingtalk.com/v1.0/contact/users/me'

    def get_authorization_url(self):
        # appid=SuiteKey&response_type=code&scope=snsapi_login&state=STATE&redirect_uri=REDIRECT_URI
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': 'openid',
            'prompt': 'consent'
        }
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def get_access_token(self, code: str):
        data = json.dumps({
            'clientId': self.client_id,
            'clientSecret': self.client_secret,
            'code': code,
            'grantType': 'authorization_code',
        })
        headers = {'Content-Type': 'application/json'}
        response = requests.request("POST", self._TOKEN_URL, data=data, headers=headers)

        response_json = response.json()
        access_token = response_json.get('accessToken')

        if not access_token:
            raise ValueError(f"Error in Google OAuth: {response_json}")

        return access_token

    def get_raw_user_info(self, token: str):
        headers = {'x-acs-dingtalk-access-token': token}
        response = requests.get(self._USER_INFO_URL, headers=headers)

        response_json = response.json()

        return response_json

    def _transform_user_info(self, raw_info: dict) -> OAuthUserInfo:
        return OAuthUserInfo(
            id=str(raw_info['openId']),
            name=raw_info['nick'],
            email=raw_info['email']
        )



