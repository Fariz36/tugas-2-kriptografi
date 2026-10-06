from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import random
import sys
from typing import Sequence

try:
    import numpy as np
except ImportError as exc:
    raise SystemExit(
        "S-box search requires optional dependency NumPy. Install with: "
        "python -m pip install -e .[sbox-search]"
    ) from exc


DEFAULT_SEED = 0xDEADBEEF
POPULATION_SIZE = 32
GENERATION_COUNT = 50
SA_STEPS = 5_000
ELITISM = 2
TOURNAMENT_SIZE = 3
CROSSOVER_RATE = 0.8
MUTATION_RATE = 0.1
SA_INITIAL_TEMPERATURE = 25.0
SA_FINAL_TEMPERATURE = 0.1

_VALUES = np.arange(256, dtype=np.uint16)
_PARITY_TABLE = np.array(
    [[((output_mask & value).bit_count() & 1) for value in range(256)] for output_mask in range(256)],
    dtype=np.int16,
)


@dataclass(frozen=True)
class SBoxMetrics:
    differential_uniformity: int
    nonlinearity: int
    sac_deviation: float
    fitness: float


def _fwht_rows(values: np.ndarray) -> None:
    width = values.shape[1]
    half = 1
    while half < width:
        reshaped = values.reshape(values.shape[0], width // (2 * half), 2, half)
        left = reshaped[:, :, 0, :].copy()
        right = reshaped[:, :, 1, :].copy()
        reshaped[:, :, 0, :] = left + right
        reshaped[:, :, 1, :] = left - right
        half *= 2


def evaluate_sbox(candidate: Sequence[int]) -> SBoxMetrics:
    if len(candidate) != 256 or set(candidate) != set(range(256)):
        raise ValueError("an S-box candidate must be a permutation of byte values 0..255")
    sbox = np.asarray(candidate, dtype=np.uint16)

    input_differences = np.arange(1, 256, dtype=np.uint16)
    output_differences = sbox[_VALUES[None, :] ^ input_differences[:, None]] ^ sbox[None, :]
    row_offsets = np.arange(1, 256, dtype=np.int64)[:, None] * 256
    ddt = np.bincount(
        (output_differences.astype(np.int64) + row_offsets).ravel(),
        minlength=256 * 256,
    ).reshape(256, 256)
    differential_uniformity = int(ddt[:, 1:].max())

    component_signs = 1 - 2 * _PARITY_TABLE[:, sbox]
    _fwht_rows(component_signs)
    max_component_walsh = int(np.abs(component_signs[1:, :]).max())
    nonlinearity = 128 - max_component_walsh // 2

    sac_deviations: list[float] = []
    for input_bit in range(8):
        changed = sbox ^ sbox[_VALUES ^ (1 << input_bit)]
        for output_bit in range(8):
            probability = float(((changed >> output_bit) & 1).mean())
            sac_deviations.append(abs(probability - 0.5))
    sac_deviation = sum(sac_deviations) / len(sac_deviations)
    fitness = 1000.0 * differential_uniformity - nonlinearity + 10.0 * sac_deviation
    return SBoxMetrics(differential_uniformity, nonlinearity, sac_deviation, fitness)


def _pmx(parent_a: list[int], parent_b: list[int], rng: random.Random) -> list[int]:
    low, high = sorted(rng.sample(range(256), 2))
    high += 1
    child: list[int | None] = [None] * 256
    segment = parent_a[low:high]
    segment_values = set(segment)
    child[low:high] = segment
    positions_b = {gene: index for index, gene in enumerate(parent_b)}

    for index in range(low, high):
        gene = parent_b[index]
        if gene in segment_values:
            continue
        target = index
        while low <= target < high:
            target = positions_b[parent_a[target]]
        child[target] = gene

    for index, gene in enumerate(parent_b):
        if child[index] is None:
            child[index] = gene
    return [int(gene) for gene in child]


def _tournament(population, rng: random.Random):
    contestants = rng.sample(population, TOURNAMENT_SIZE)
    return min(contestants, key=lambda item: item[1])


def _random_swap(candidate: list[int], rng: random.Random) -> list[int]:
    result = candidate.copy()
    left, right = rng.sample(range(256), 2)
    result[left], result[right] = result[right], result[left]
    return result


def search_sbox(
    *,
    seed: int = DEFAULT_SEED,
    population_size: int = POPULATION_SIZE,
    generations: int = GENERATION_COUNT,
    sa_steps: int = SA_STEPS,
) -> tuple[list[int], SBoxMetrics]:
    if population_size < ELITISM + TOURNAMENT_SIZE:
        raise ValueError("population size must be at least 5")
    if generations < 0 or sa_steps < 0:
        raise ValueError("generation and SA step counts cannot be negative")

    rng = random.Random(seed)
    population = []
    for _ in range(population_size):
        candidate = rng.sample(range(256), 256)
        population.append((candidate, evaluate_sbox(candidate).fitness))

    for _ in range(generations):
        population.sort(key=lambda item: item[1])
        next_population = population[:ELITISM]
        while len(next_population) < population_size:
            parent_a = _tournament(population, rng)[0]
            parent_b = _tournament(population, rng)[0]
            child = (
                _pmx(parent_a, parent_b, rng)
                if rng.random() < CROSSOVER_RATE
                else parent_a.copy()
            )
            if rng.random() < MUTATION_RATE:
                child = _random_swap(child, rng)
            next_population.append((child, evaluate_sbox(child).fitness))
        population = next_population

    population.sort(key=lambda item: item[1])
    current = population[0][0].copy()
    current_metrics = evaluate_sbox(current)
    best = current.copy()
    best_metrics = current_metrics

    for step in range(sa_steps):
        candidate = _random_swap(current, rng)
        metrics = evaluate_sbox(candidate)
        temperature = SA_INITIAL_TEMPERATURE * (
            SA_FINAL_TEMPERATURE / SA_INITIAL_TEMPERATURE
        ) ** (step / max(sa_steps - 1, 1))
        delta = metrics.fitness - current_metrics.fitness
        if delta <= 0 or rng.random() < math.exp(-delta / temperature):
            current, current_metrics = candidate, metrics
        if metrics.fitness < best_metrics.fitness:
            best, best_metrics = candidate, metrics

    return best, best_metrics


def _format_python_table(table: Sequence[int], name: str) -> str:
    lines = [f"{name} = (\n"]
    for offset in range(0, 256, 16):
        values = ", ".join(f"0x{value:02X}" for value in table[offset : offset + 16])
        lines.append(f"    {values},\n")
    lines.append(")\n")
    return "".join(lines)


def write_outputs(
    sbox: Sequence[int],
    metrics: SBoxMetrics,
    seed: int,
    source_path: Path,
    population_size: int,
    generations: int,
    sa_steps: int,
) -> None:
    inverse = [0] * 256
    for input_value, output_value in enumerate(sbox):
        inverse[output_value] = input_value

    source_path.parent.mkdir(parents=True, exist_ok=True)
    source = (
        _format_python_table(sbox, "SBOX")
        + "\n"
        + _format_python_table(inverse, "INV_SBOX")
    )
    source_path.write_text(source, encoding="utf-8")
    metadata = {
        "algorithm": "GA followed by simulated annealing",
        "seed": seed,
        "population_size": population_size,
        "generations": generations,
        "sa_steps": sa_steps,
        "metrics": asdict(metrics),
    }
    source_path.with_name("sbox_metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the JAV-128 S-box")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=DEFAULT_SEED)
    parser.add_argument("--population", type=int, default=POPULATION_SIZE)
    parser.add_argument("--generations", type=int, default=GENERATION_COUNT)
    parser.add_argument("--sa-steps", type=int, default=SA_STEPS)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src" / "jav128" / "sbox.py",
    )
    args = parser.parse_args(argv)
    sbox, metrics = search_sbox(
        seed=args.seed,
        population_size=args.population,
        generations=args.generations,
        sa_steps=args.sa_steps,
    )
    write_outputs(
        sbox,
        metrics,
        args.seed,
        args.output,
        args.population,
        args.generations,
        args.sa_steps,
    )
    print(json.dumps(asdict(metrics), indent=2))
    print(f"Wrote {args.output} and {args.output.with_name('sbox_metadata.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
