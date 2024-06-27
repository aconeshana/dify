from typing import Optional

from pydantic import BaseModel, Field


class DingtalkConfig(BaseModel):
    """
    Notion integration configs
    """
    DINGTALK_APP_KEY: Optional[str] = Field(
        description='dingtalk ak',
        default=None,
    )

    DINGTALK_APP_SECRET: Optional[str] = Field(
        description='dingtalk sk',
        default=None,
    )
