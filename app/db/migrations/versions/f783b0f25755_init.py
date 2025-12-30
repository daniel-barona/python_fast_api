"""init

Revision ID: f783b0f25755
Revises: 6158fc7f1572
Create Date: 2025-12-29 14:00:13.230093

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f783b0f25755'
down_revision: Union[str, Sequence[str], None] = '6158fc7f1572'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
