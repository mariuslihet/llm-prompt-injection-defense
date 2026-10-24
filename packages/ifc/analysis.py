"""Static data-flow graph for the finite SSA program, without invoking any tools."""

from collections import deque

from pydantic import BaseModel, ConfigDict

from packages.core import Confidentiality, Trust, Value
from packages.ifc import Concat, Extract, Program
from packages.policy import Policy, evaluate, verify


class FlowPath(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source: str
    sink: str
    nodes: tuple[str, ...]


class FlowReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    edges: tuple[tuple[str, str], ...]
    private_paths: tuple[FlowPath, ...]
    untrusted_paths: tuple[FlowPath, ...]
    guarded_sinks: tuple[str, ...]
    violations: tuple[str, ...]


def analyze(program: Program, inputs: dict[str, Value], policy: Policy) -> FlowReport:
    values = inputs.copy()
    edges: list[tuple[str, str]] = []
    sinks: list[str] = []
    guarded = []
    problems = verify(policy)
    untrusted = any(value.label.trust == Trust.UNTRUSTED for value in inputs.values())
    for index, instruction in enumerate(program.instructions):
        if isinstance(instruction, Extract | Concat):
            if instruction.output in values:
                raise ValueError("static SSA overwrite")
            if isinstance(instruction, Extract):
                values[instruction.output] = values[instruction.source].transform("")
                edges.append((instruction.source, instruction.output))
            else:
                values[instruction.output] = values[instruction.left].concat(
                    values[instruction.right]
                )
                edges.extend(
                    [
                        (instruction.left, instruction.output),
                        (instruction.right, instruction.output),
                    ]
                )
        else:
            arguments = {
                name: values[reference] for name, reference in instruction.arguments.items()
            }
            rule = next((rule for rule in policy.rules if rule.tool == instruction.tool), None)
            if rule is None:
                problems.append(f"unknown tool at call {index}")
                continue
            decision = evaluate(policy, instruction.tool, arguments, read_untrusted=untrusted)
            if rule.external:
                sink = f"call:{index}:{instruction.tool}"
                sinks.append(sink)
                edges.extend((reference, sink) for reference in instruction.arguments.values())
                # Implicit control dependencies are explicit graph edges too.
                edges.extend(
                    (name, sink)
                    for name, value in inputs.items()
                    if value.label.trust == Trust.UNTRUSTED
                )
                if not decision.allowed:
                    guarded.append(sink)
    adjacency: dict[str, list[str]] = {}
    for source, target in edges:
        adjacency.setdefault(source, []).append(target)

    def paths(private: bool) -> tuple[FlowPath, ...]:
        result = []
        for name, value in inputs.items():
            qualifies = (
                value.label.confidentiality == Confidentiality.PRIVATE
                if private
                else value.label.trust == Trust.UNTRUSTED
            )
            if not qualifies:
                continue
            queue: deque[tuple[str, tuple[str, ...]]] = deque([(name, (name,))])
            visited = {name}
            while queue:
                node, path = queue.popleft()
                if node in sinks:
                    result.append(FlowPath(source=name, sink=node, nodes=path))
                for target in adjacency.get(node, []):
                    if target not in visited:
                        visited.add(target)
                        queue.append((target, (*path, target)))
        return tuple(result)

    private_paths, untrusted_paths = paths(True), paths(False)
    joined = {path.sink for path in private_paths} & {path.sink for path in untrusted_paths}
    for sink in joined - set(guarded):
        problems.append(f"private and untrusted sources reach unguarded {sink}")
    return FlowReport(
        edges=tuple(sorted(set(edges))),
        private_paths=private_paths,
        untrusted_paths=untrusted_paths,
        guarded_sinks=tuple(guarded),
        violations=tuple(problems),
    )
