from pydantic import BaseModel

from configs.oauth.dingtalk_oauth2_config import DingtalkConfig


class OauthConfig(
    # place the configs in alphabet order
    DingtalkConfig,
):
    pass
