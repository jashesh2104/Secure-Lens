"""add reachability, priority, verified_fix to findings

Revision ID: b7c9d1e2f3a4
Revises: f9fa39284e81
Create Date: 2026-09-04 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7c9d1e2f3a4'
down_revision: Union[str, None] = 'f9fa39284e81'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reachability', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('priority', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('verified_fix', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_column('verified_fix')
        batch_op.drop_column('priority')
        batch_op.drop_column('reachability')
