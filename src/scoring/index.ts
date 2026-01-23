/**
 * Security Score Calculator
 *
 * Calculates a 0-100 security score based on findings severity.
 * Uses a penalty-based diminishing returns formula to prevent negative scores.
 */

// Scoring weights
const WEIGHTS = {
  critical: 15,
  high: 8,
  medium: 3,
  low: 1
};

// Grade thresholds
const GRADES = [
  { min: 90, grade: 'A', color: '#3fb950' },
  { min: 70, grade: 'B', color: '#58a6ff' },
  { min: 50, grade: 'C', color: '#d29922' },
  { min: 0, grade: 'F', color: '#f85149' }
];

export interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SecurityScore {
  score: number;
  grade: string;
  gradeColor: string;
  breakdown: {
    critical: { count: number; penalty: number };
    high: { count: number; penalty: number };
    medium: { count: number; penalty: number };
    low: { count: number; penalty: number };
    totalPenalty: number;
  };
}

export interface ScoreHistoryEntry {
  id: number;
  target: string;
  auditId: string;
  score: number;
  grade: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  timestamp: string;
}

export interface ScoreTrend {
  currentScore: number;
  previousScore: number | null;
  change: number;
  direction: 'up' | 'down' | 'same';
  history: Array<{ timestamp: string; score: number }>;
}

/**
 * Calculate security score from finding counts
 */
export function calculateSecurityScore(counts: FindingCounts): SecurityScore {
  const critical = counts.critical || 0;
  const high = counts.high || 0;
  const medium = counts.medium || 0;
  const low = counts.low || 0;

  // Calculate penalties
  const criticalPenalty = critical * WEIGHTS.critical;
  const highPenalty = high * WEIGHTS.high;
  const mediumPenalty = medium * WEIGHTS.medium;
  const lowPenalty = low * WEIGHTS.low;
  const totalPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty;

  // Diminishing returns formula: score = 100 / (1 + penalty/100)
  // This ensures score stays between 0-100 and degrades smoothly
  const score = Math.round(100 / (1 + totalPenalty / 100));

  // Get grade
  const gradeInfo = GRADES.find(g => score >= g.min) || GRADES[GRADES.length - 1];

  return {
    score,
    grade: gradeInfo.grade,
    gradeColor: gradeInfo.color,
    breakdown: {
      critical: { count: critical, penalty: criticalPenalty },
      high: { count: high, penalty: highPenalty },
      medium: { count: medium, penalty: mediumPenalty },
      low: { count: low, penalty: lowPenalty },
      totalPenalty
    }
  };
}

/**
 * Calculate trend from score history
 */
export function calculateTrend(history: ScoreHistoryEntry[]): ScoreTrend {
  if (history.length === 0) {
    return {
      currentScore: 100,
      previousScore: null,
      change: 0,
      direction: 'same',
      history: []
    };
  }

  const current = history[0];
  const previous = history.length > 1 ? history[1] : null;
  const change = previous ? current.score - previous.score : 0;

  let direction: 'up' | 'down' | 'same' = 'same';
  if (change > 0) direction = 'up';
  else if (change < 0) direction = 'down';

  return {
    currentScore: current.score,
    previousScore: previous?.score || null,
    change: Math.abs(change),
    direction,
    history: history.map(h => ({ timestamp: h.timestamp, score: h.score }))
  };
}

/**
 * Generate SVG badge for security score
 */
export function generateScoreBadge(score: number, grade: string, gradeColor: string): string {
  const labelText = 'security';
  const valueText = `${score} ${grade}`;

  // Calculate widths (approximate character width)
  const labelWidth = labelText.length * 7 + 10;
  const valueWidth = valueText.length * 7 + 10;
  const totalWidth = labelWidth + valueWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" viewBox="0 0 ${totalWidth} 20">
  <linearGradient id="smooth" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="round">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#round)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${gradeColor}"/>
    <rect width="${totalWidth}" height="20" fill="url(#smooth)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${labelText}</text>
    <text x="${labelWidth / 2}" y="14" fill="#fff">${labelText}</text>
    <text x="${labelWidth + valueWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${valueText}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14" fill="#fff">${valueText}</text>
  </g>
</svg>`;
}
