function metrics(vector: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const part of vector
    .trim()
    .replace(/^\(|\)$/g, "")
    .split("/")) {
    const [key, value] = part.split(":");
    if (key && value) values[key.toUpperCase()] = value.toUpperCase();
  }
  return values;
}

function roundUp(score: number): number {
  const scaled = Math.round(score * 100_000);
  return scaled % 10_000 === 0
    ? scaled / 100_000
    : (Math.floor(scaled / 10_000) + 1) / 10;
}

function cvssV3(vector: string): number | null {
  const value = metrics(vector);
  const av: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const ac: Record<string, number> = { L: 0.77, H: 0.44 };
  const prUnchanged: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const prChanged: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
  const ui: Record<string, number> = { N: 0.85, R: 0.62 };
  const cia: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const scope = value.S;
  const avMetric = value.AV;
  const acMetric = value.AC;
  const prMetric = value.PR;
  const uiMetric = value.UI;
  const cMetric = value.C;
  const iMetric = value.I;
  const aMetric = value.A;
  if (
    !scope ||
    !avMetric ||
    !acMetric ||
    !prMetric ||
    !uiMetric ||
    !cMetric ||
    !iMetric ||
    !aMetric
  ) {
    return null;
  }
  const privilege = scope === "C" ? prChanged[prMetric] : prUnchanged[prMetric];
  const fields = [
    av[avMetric],
    ac[acMetric],
    privilege,
    ui[uiMetric],
    cia[cMetric],
    cia[iMetric],
    cia[aMetric],
  ];
  if (scope === undefined || fields.some((field) => field === undefined)) {
    return null;
  }
  const impactSubScore =
    1 - (1 - cia[cMetric]!) * (1 - cia[iMetric]!) * (1 - cia[aMetric]!);
  const impact =
    scope === "C"
      ? 7.52 * (impactSubScore - 0.029) -
        3.25 * Math.pow(impactSubScore - 0.02, 15)
      : 6.42 * impactSubScore;
  if (impact <= 0) return 0;
  const exploitability =
    8.22 * av[avMetric]! * ac[acMetric]! * privilege! * ui[uiMetric]!;
  return roundUp(
    Math.min(
      scope === "C"
        ? 1.08 * (impact + exploitability)
        : impact + exploitability,
      10,
    ),
  );
}

/** Calculates a base score from a CVSS v3 vector emitted by OSV. */
export function parseCvssVector(vector: string): number | null {
  return vector.trim().startsWith("CVSS:3") ? cvssV3(vector) : null;
}
