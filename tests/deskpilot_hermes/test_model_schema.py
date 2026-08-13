"""The model-facing schema must render on the pinned model.

gemma-4-e4b's chat template crashes under LM Studio's Jinja engine when a tool
schema carries `enum`: a bare `{enum: [...]}` raises `Cannot apply filter
"upper" to type: UndefinedValue`, and even `{type: string, enum: [...]}` raises
`Unknown test: sequence`. Every tool ships in one request, so a single bad
schema poisons the whole turn.

The fix narrows only what the model is shown. Authorization has never depended
on the model honouring its schema — ActionRegistry validates inputs and is the
enforcement point — so dropping `enum` from the model-facing copy costs no
safety, provided the registry keeps it. The last test here pins that proviso.
"""

import copy

import pytest

from tools.deskpilot_actions_tool import _model_facing_schema


def test_enum_is_replaced_by_a_typed_field_that_names_the_values():
    schema = {
        "type": "object",
        "properties": {"bundleID": {"enum": ["dev.zed.Zed", "com.mitchellh.ghostty"]}},
        "required": ["bundleID"],
        "additionalProperties": False,
    }
    rendered = _model_facing_schema(schema)
    field = rendered["properties"]["bundleID"]
    assert "enum" not in field
    assert field["type"] == "string"
    # The permitted values must survive as guidance, or the model cannot choose.
    assert "dev.zed.Zed" in field["description"]
    assert "com.mitchellh.ghostty" in field["description"]


def test_the_validation_schema_is_never_mutated():
    schema = {
        "type": "object",
        "properties": {"bundleID": {"enum": ["dev.zed.Zed"]}},
    }
    original = copy.deepcopy(schema)
    _model_facing_schema(schema)
    assert schema == original, "enforcement schema must survive untouched"


def test_nested_and_array_schemas_are_reached():
    schema = {
        "type": "object",
        "properties": {
            "window": {
                "type": "object",
                "properties": {"edge": {"enum": ["left", "right"]}},
            },
            "targets": {"type": "array", "items": {"enum": ["a", "b"]}},
        },
    }
    rendered = _model_facing_schema(schema)
    assert "enum" not in rendered["properties"]["window"]["properties"]["edge"]
    assert "enum" not in rendered["properties"]["targets"]["items"]


def test_an_existing_description_is_kept_alongside_the_values():
    schema = {"properties": {"mode": {"enum": ["a"], "description": "How to run."}}}
    description = _model_facing_schema(schema)["properties"]["mode"]["description"]
    assert "How to run." in description and "a" in description


def test_non_string_enums_keep_a_faithful_type():
    schema = {"properties": {"count": {"enum": [1, 2, 3]}}}
    assert _model_facing_schema(schema)["properties"]["count"]["type"] == "integer"


def test_const_is_folded_in_the_same_way():
    # const is enum with one member and breaks the template identically. Two
    # shipped actions use it, which is why enum-only handling was not enough.
    rendered = _model_facing_schema({"properties": {"scope": {"const": "all"}}})
    field = rendered["properties"]["scope"]
    assert "const" not in field
    assert field["type"] == "string" and "all" in field["description"]


def test_no_property_reaches_the_model_without_a_type():
    # The template applies `| upper` to a property's type; an undefined one
    # aborts the whole request, not just that tool.
    from tools.deskpilot_actions_tool import get_expected_deskpilot_definitions

    untyped = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    for name, field in value.items():
                        if isinstance(field, dict) and "type" not in field:
                            untyped.append(f"{path}.{name}")
                        walk(field, f"{path}.{name}")
                else:
                    walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(get_expected_deskpilot_definitions(), "")
    assert untyped == [], f"untyped properties reach the model at: {untyped}"


def test_every_shipped_definition_is_free_of_enum_and_const():
    # The whole tool set goes in one request; one bad schema breaks the turn.
    from tools.deskpilot_actions_tool import get_expected_deskpilot_definitions

    def find(node, path="") -> list[str]:
        found = []
        if isinstance(node, dict):
            for keyword in ("enum", "const"):
                if keyword in node:
                    found.append(f"{path}:{keyword}")
            for key, value in node.items():
                found += find(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                found += find(value, f"{path}[{index}]")
        return found

    offenders = find(get_expected_deskpilot_definitions())
    assert offenders == [], f"unrenderable keywords reach the model at: {offenders}"


def test_the_registry_still_rejects_a_value_the_model_could_now_invent():
    # The load-bearing test for this whole change: removing enum from the
    # model's copy must not widen what is actually executable.
    from tools.deskpilot_actions_tool import load_packaged_action_registry

    registry = load_packaged_action_registry()
    with pytest.raises(Exception):
        registry.resolve("app.focus", 1, {"bundleID": "com.evil.NotOnTheList"})


def test_the_enforcement_schema_keeps_its_enum():
    from tools.deskpilot_actions_tool import load_packaged_action_registry

    spec = load_packaged_action_registry()._specs[("app.focus", 1)]
    assert "enum" in spec.inputSchema["properties"]["bundleID"]
