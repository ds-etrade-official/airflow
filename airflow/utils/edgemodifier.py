# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from typing import List, Optional, Sequence, Union

from airflow.models.taskmixin import DAGNode, DependencyMixin


class EdgeModifier(DependencyMixin):
    """
    Class that represents edge information to be added between two
    tasks/operators. Has shorthand factory functions, like Label("hooray").

    Current implementation supports
        t1 >> Label("Success route") >> t2
        t2 << Label("Success route") << t2

    Note that due to the potential for use in either direction, this waits
    to make the actual connection between both sides until both are declared,
    and will do so progressively if multiple ups/downs are added.

    This and EdgeInfo are related - an EdgeModifier is the Python object you
    use to add information to (potentially multiple) edges, and EdgeInfo
    is the representation of the information for one specific edge.
    """

    def __init__(self, label: Optional[str] = None):
        self.label = label
        self._upstream: List["DependencyMixin"] = []
        self._downstream: List["DependencyMixin"] = []

    @property
    def roots(self):
        return self._downstream

    @property
    def leaves(self):
        return self._upstream

    @staticmethod
    def _make_list(item_or_list):
        if not isinstance(item_or_list, Sequence):
            return [item_or_list]
        return item_or_list

    def _save_nodes(
        self,
        nodes: Union["DependencyMixin", Sequence["DependencyMixin"]],
        stream: List["DependencyMixin"],
    ):
        from airflow.models.xcom_arg import XComArg
        from airflow.utils.task_group import TaskGroup

        for node in self._make_list(nodes):
            if isinstance(node, (TaskGroup, XComArg)):
                stream.append(node)
            elif isinstance(node, DAGNode):
                if node.task_group and not node.task_group.is_root:
                    stream.append(node.task_group)
                else:
                    stream.append(node)
            else:
                raise TypeError(
                    f"Cannot use edge labels with {type(node).__name__}, "
                    f"only tasks, XComArg or TaskGroups"
                )

    def set_upstream(
        self,
        other: Union["DependencyMixin", Sequence["DependencyMixin"]],
        edge_modifier: Optional["EdgeModifier"] = None,
    ):
        """
        Sets the given task/list onto the upstream attribute, and then checks if
        we have both sides so we can resolve the relationship.

        Providing this also provides << via DependencyMixin.
        """
        self._save_nodes(other, self._upstream)
        for node in self._downstream:
            node.set_upstream(other, edge_modifier=self)

    def set_downstream(
        self,
        other: Union["DependencyMixin", Sequence["DependencyMixin"]],
        edge_modifier: Optional["EdgeModifier"] = None,
    ):
        """
        Sets the given task/list onto the downstream attribute, and then checks if
        we have both sides so we can resolve the relationship.

        Providing this also provides >> via DependencyMixin.
        """
        self._save_nodes(other, self._downstream)
        for node in self._upstream:
            node.set_downstream(other, edge_modifier=self)

    def update_relative(
        self,
        other: "DependencyMixin",
        upstream: bool = True,
        edge_modifier: Optional["EdgeModifier"] = None,
    ) -> None:
        """
        Called if we're not the "main" side of a relationship; we still run the
        same logic, though.
        """
        if upstream:
            self.set_upstream(other)
        else:
            self.set_downstream(other)

    def add_edge_info(self, dag, upstream_id: str, downstream_id: str):
        """
        Adds or updates task info on the DAG for this specific pair of tasks.

        Called either from our relationship trigger methods above, or directly
        by set_upstream/set_downstream in operators.
        """
        dag.set_edge_info(upstream_id, downstream_id, {"label": self.label})


# Factory functions
def Label(label: str):
    """Creates an EdgeModifier that sets a human-readable label on the edge."""
    return EdgeModifier(label=label)
