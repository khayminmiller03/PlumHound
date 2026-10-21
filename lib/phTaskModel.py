from typing import Literal

from pydantic import BaseModel, ConfigDict


class Task(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str
    type: Literal["cypher", "directive"]
    format: str
    output: str
    category: str = "Uncategorized"
    cypher: str
