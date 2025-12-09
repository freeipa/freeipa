"""
Certificate profile parser

This module parses certificate profile .cfg files into structured Python
objects with full support for variable substitution, policy chains, and
plugin loading.
"""

import re
import logging
from typing import Dict, Optional
from string import Template

from ipathinca.profile import (
    Profile,
    PolicyRule,
    InputPlugin,
    OutputPlugin,
)

logger = logging.getLogger(__name__)


class ProfileParser:
    """Parser for certificate profile .cfg files

    Parses Java properties-style profile configuration files and creates
    Profile objects with instantiated constraint and default plugins.
    """

    def __init__(self, profile_path: str, content: Optional[str] = None):
        """Initialize parser

        Args:
            profile_path: Path to .cfg profile file (used for profile ID
                          extraction from filename; file is not read if
                          content is provided)
            content: Optional .cfg content string.  When provided the file
                     at profile_path is not read — useful for LDAP-stored
                     profiles to avoid unnecessary temp-file I/O.
        """
        self.profile_path = profile_path
        self._content = content
        self.config: Dict[str, str] = {}

    def parse(self, context: Optional[Dict[str, str]] = None) -> Profile:
        """Parse .cfg file into Profile object

        Args:
            context: Variable substitution context

        Returns:
            Parsed Profile object
        """
        context = context or {}

        # Load and parse configuration
        self._load_config()

        # Extract profile metadata
        # If profileId is not in .cfg, use filename (without .cfg extension)
        from pathlib import Path

        default_profile_id = Path(self.profile_path).stem
        profile_id = self.config.get("profileId", default_profile_id)
        if not profile_id:  # If explicitly set to empty, use filename
            profile_id = default_profile_id

        class_id = self.config.get("classId", "")
        name = self.config.get("name", "")
        description = self.config.get("desc", "")
        enabled = self.config.get("enable", "false").lower() == "true"
        visible = self.config.get("visible", "false").lower() == "true"
        auth_instance_id = self.config.get("auth.instance_id")
        enabled_by = self.config.get("enableBy")

        # Parse inputs
        inputs = self._parse_inputs()

        # Parse outputs
        outputs = self._parse_outputs()

        # Parse policy set
        policyset_name, policies = self._parse_policyset(context)

        # Create profile object
        profile = Profile(
            profile_id=profile_id,
            class_id=class_id,
            name=name,
            description=description,
            enabled=enabled,
            visible=visible,
            auth_instance_id=auth_instance_id,
            enabled_by=enabled_by,
            inputs=inputs,
            outputs=outputs,
            policyset_name=policyset_name,
            policies=policies,
            raw_config=self.config.copy(),
        )

        return profile

    def _load_config(self):
        """Load configuration from .cfg file or content string

        Parses Java properties format: key=value
        """
        if self._content is not None:
            lines = self._content.splitlines()
        else:
            with open(self.profile_path, "r") as f:
                lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Split on first '=' only
            if "=" in line:
                key, value = line.split("=", 1)
                self.config[key.strip()] = value.strip()

    def _parse_inputs(self) -> list:
        """Parse input plugin list"""
        inputs = []
        input_list = self.config.get("input.list", "").split(",")

        for input_id in input_list:
            input_id = input_id.strip()
            if not input_id:
                continue

            class_id = self.config.get(f"input.{input_id}.class_id", "")
            inputs.append(InputPlugin(input_id=input_id, class_id=class_id))

        return inputs

    def _parse_outputs(self) -> list:
        """Parse output plugin list"""
        outputs = []
        output_list = self.config.get("output.list", "").split(",")

        for output_id in output_list:
            output_id = output_id.strip()
            if not output_id:
                continue

            class_id = self.config.get(f"output.{output_id}.class_id", "")
            outputs.append(
                OutputPlugin(output_id=output_id, class_id=class_id)
            )

        return outputs

    def _parse_policyset(self, context: dict) -> tuple:
        """Parse policy set and policy chain

        Args:
            context: Variable substitution context

        Returns:
            Tuple of (policyset_name, list of PolicyRule objects)
        """
        # Get policyset list (usually only one)
        policyset_list = self.config.get("policyset.list", "").split(",")
        if not policyset_list or not policyset_list[0]:
            return "", []

        policyset_name = policyset_list[0].strip()

        # Get policy numbers in this set
        policy_numbers_str = self.config.get(
            f"policyset.{policyset_name}.list", ""
        )
        policy_numbers = [
            int(n.strip()) for n in policy_numbers_str.split(",") if n.strip()
        ]

        # Parse each policy
        policies = []
        for num in sorted(policy_numbers):
            policy = self._parse_policy(policyset_name, num, context)
            if policy:
                policies.append(policy)

        return policyset_name, policies

    def _parse_policy(
        self, policyset_name: str, policy_num: int, context: dict
    ) -> Optional[PolicyRule]:
        """Parse a single policy rule

        Args:
            policyset_name: Name of the policy set
            policy_num: Policy number
            context: Variable substitution context

        Returns:
            PolicyRule object or None
        """
        prefix = f"policyset.{policyset_name}.{policy_num}"

        # Get constraint info
        constraint_class = self.config.get(f"{prefix}.constraint.class_id", "")
        constraint_name = self.config.get(f"{prefix}.constraint.name", "")

        # Get default info
        default_class = self.config.get(f"{prefix}.default.class_id", "")
        default_name = self.config.get(f"{prefix}.default.name", "")

        if not constraint_class or not default_class:
            logger.warning(
                "Policy %s missing constraint or default class", policy_num
            )
            return None

        # Extract parameters for constraint
        constraint_params = self._extract_params(
            f"{prefix}.constraint.params", context
        )

        # Extract parameters for default
        default_params = self._extract_params(
            f"{prefix}.default.params", context
        )

        # Import constraint and default factories
        from ipathinca.profile_constraints import create_constraint
        from ipathinca.profile_defaults import create_default

        # Create constraint and default instances
        try:
            constraint = create_constraint(constraint_class, constraint_params)
            default = create_default(default_class, default_params)
        except Exception as e:
            logger.error(
                "Failed to create policy %s plugins: %s", policy_num, e
            )
            return None

        return PolicyRule(
            number=policy_num,
            constraint_name=constraint_name,
            constraint=constraint,
            default_name=default_name,
            default=default,
        )

    def _extract_params(self, prefix: str, context: dict) -> dict:
        """Extract all parameters with given prefix

        Args:
            prefix: Parameter prefix
                    (e.g., 'policyset.set1.1.constraint.params')
            context: Variable substitution context

        Returns:
            Dictionary of parameter names to values
        """
        params = {}
        prefix_dot = prefix + "."

        for key, value in self.config.items():
            if key.startswith(prefix_dot):
                param_name = key[len(prefix_dot) :]
                # Perform variable substitution
                value = self.substitute_variables(value, context)
                params[param_name] = value

        return params

    def substitute_variables(self, text: str, context: dict) -> str:
        """Perform variable substitution on text

        Supports:
        - $VAR - Simple variable substitution
        - $$request.field$$ - Request context extraction (handled later)

        Args:
            text: Text containing variables
            context: Substitution context

        Returns:
            Text with variables substituted
        """
        if not text:
            return text

        logger.debug("substitute_variables input: %s", text)
        logger.debug("substitute_variables context: %s", context)

        # Protect $$request.X$$ variables from Template substitution
        # Template treats $$ as escape for literal $, which would mangle our
        # syntax
        # Replace $$request.X$$ with a placeholder, do substitution, then
        # restore

        placeholders = {}
        counter = 0

        # Find and protect all $$request.X$$ variables
        request_pattern = r"\$\$request\.[^$]+\$\$"

        def protect_request_var(match):
            nonlocal counter
            placeholder = f"___PLACEHOLDER_{counter}___"
            placeholders[placeholder] = match.group(0)
            counter += 1
            return placeholder

        text = re.sub(request_pattern, protect_request_var, text)

        # Now do simple $VAR substitution with Template
        try:
            template = Template(text)
            text = template.safe_substitute(context)
        except Exception as e:
            logger.warning("Variable substitution failed: %s", e)

        # Restore $$request.X$$ variables
        for placeholder, original in placeholders.items():
            text = text.replace(placeholder, original)

        # $$request.X$$ substitution is handled at runtime in defaults
        # since request context is not available during parsing

        logger.debug("substitute_variables output: %s", text)
        return text
