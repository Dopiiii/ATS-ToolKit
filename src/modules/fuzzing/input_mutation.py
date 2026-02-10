"""Input Mutation Module.

Mutate valid inputs using various strategies to discover edge-case bugs and crashes.
"""

import asyncio
import os
import random
import struct
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Boundary values commonly used in fuzzing
BOUNDARY_VALUES: List[bytes] = [
    b"\x00", b"\xff", b"\x00" * 4, b"\xff" * 4,
    struct.pack("<i", 0), struct.pack("<i", -1),
    struct.pack("<i", 2147483647), struct.pack("<i", -2147483648),
    struct.pack("<H", 0), struct.pack("<H", 65535),
    b"\x00" * 256, b"\xff" * 256,
]


class InputMutationModule(AtsModule):
    """Mutate valid inputs using multiple strategies to discover bugs."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="input_mutation",
            category=ModuleCategory.FUZZING,
            description="Mutate valid inputs using bit-flipping, byte insertion, boundary values, and more",
            version="1.0.0",
            parameters=[
                Parameter(name="base_input", type=ParameterType.STRING, description="Base input string to mutate", required=True),
                Parameter(name="num_mutations", type=ParameterType.INTEGER, description="Number of mutations to generate", required=False, default=50, min_value=1, max_value=10000),
                Parameter(name="strategies", type=ParameterType.LIST, description="Mutation strategies to use", required=False, default=["bit_flip", "byte_insert", "boundary", "type_confusion", "truncation", "repetition"]),
                Parameter(name="seed", type=ParameterType.INTEGER, description="Random seed for reproducibility", required=False, default=None),
            ],
            outputs=[
                OutputField(name="mutations", type="list", description="Generated mutation cases with metadata"),
                OutputField(name="summary", type="dict", description="Mutation generation summary"),
            ],
            requires_api_key=False,
            api_key_service=None,
            tags=["fuzzing", "mutation", "input", "testing"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        base = config.get("base_input", "")
        if not base:
            return False, "base_input is required and cannot be empty"
        valid_strategies = {"bit_flip", "byte_insert", "boundary", "type_confusion", "truncation", "repetition"}
        chosen = config.get("strategies", list(valid_strategies))
        for s in chosen:
            if s not in valid_strategies:
                return False, f"Unknown strategy: {s}. Valid: {sorted(valid_strategies)}"
        return True, ""

    def _bit_flip(self, data: bytearray) -> bytearray:
        """Flip a random bit in the data."""
        if not data:
            return data
        result = bytearray(data)
        pos = random.randint(0, len(result) - 1)
        bit = random.randint(0, 7)
        result[pos] ^= 1 << bit
        return result

    def _byte_insert(self, data: bytearray) -> bytearray:
        """Insert random bytes at a random position."""
        result = bytearray(data)
        pos = random.randint(0, len(result))
        num_bytes = random.randint(1, 16)
        insert_data = bytearray(random.randint(0, 255) for _ in range(num_bytes))
        return result[:pos] + insert_data + result[pos:]

    def _boundary(self, data: bytearray) -> bytearray:
        """Replace a portion with boundary values."""
        result = bytearray(data)
        if not result:
            return result
        bval = random.choice(BOUNDARY_VALUES)
        pos = random.randint(0, max(0, len(result) - 1))
        end = min(pos + len(bval), len(result))
        result[pos:end] = bval[:end - pos]
        return result

    def _type_confusion(self, data: bytearray) -> bytearray:
        """Replace content with a different type representation."""
        confusions = [
            b"null", b"true", b"false", b"undefined", b"NaN",
            b"0", b"-1", b"[]", b"{}", b"0.0",
            b"\x00\x00\x00\x00", b"Array", b"Object",
        ]
        return bytearray(random.choice(confusions))

    def _truncation(self, data: bytearray) -> bytearray:
        """Truncate the data at a random position."""
        if len(data) <= 1:
            return bytearray()
        cut = random.randint(0, len(data) - 1)
        return bytearray(data[:cut])

    def _repetition(self, data: bytearray) -> bytearray:
        """Repeat portions of data to create oversized input."""
        if not data:
            return data
        start = random.randint(0, max(0, len(data) - 1))
        end = random.randint(start + 1, len(data))
        chunk = data[start:end]
        repeat_count = random.randint(2, 100)
        return bytearray(data[:start]) + chunk * repeat_count + bytearray(data[end:])

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        base_input = config["base_input"]
        num_mutations = config.get("num_mutations", 50)
        strategies = config.get("strategies", ["bit_flip", "byte_insert", "boundary", "type_confusion", "truncation", "repetition"])
        seed = config.get("seed")

        if seed is not None:
            random.seed(seed)

        self.logger.info("mutation_start", base_len=len(base_input), count=num_mutations)

        strategy_map = {
            "bit_flip": self._bit_flip,
            "byte_insert": self._byte_insert,
            "boundary": self._boundary,
            "type_confusion": self._type_confusion,
            "truncation": self._truncation,
            "repetition": self._repetition,
        }

        base_bytes = bytearray(base_input.encode("utf-8", errors="replace"))
        mutations: List[Dict[str, Any]] = []
        strategy_counts: Dict[str, int] = {s: 0 for s in strategies}

        for i in range(num_mutations):
            strategy_name = random.choice(strategies)
            mutator = strategy_map[strategy_name]
            mutated = mutator(bytearray(base_bytes))

            try:
                mutated_str = mutated.decode("utf-8", errors="replace")
            except Exception:
                mutated_str = mutated.hex()

            mutations.append({
                "index": i,
                "strategy": strategy_name,
                "original_length": len(base_bytes),
                "mutated_length": len(mutated),
                "mutated_preview": mutated_str[:500],
                "mutated_hex_preview": mutated[:64].hex(),
                "is_printable": mutated_str.isprintable(),
            })
            strategy_counts[strategy_name] += 1

        size_stats = [m["mutated_length"] for m in mutations]
        summary = {
            "base_input_length": len(base_bytes),
            "total_mutations": len(mutations),
            "strategies_used": strategy_counts,
            "min_output_size": min(size_stats) if size_stats else 0,
            "max_output_size": max(size_stats) if size_stats else 0,
            "avg_output_size": sum(size_stats) / len(size_stats) if size_stats else 0,
            "seed": seed,
        }

        self.logger.info("mutation_complete", total=len(mutations))
        return {"mutations": mutations, "summary": summary}
