import type { AssessmentLevel } from '../../features/pdf-analysis/types/analysis';

/** Short names for assessment levels, used in badges, announcements and the page title. */
export const LEVEL_LABELS: Record<AssessmentLevel, string> = {
  'none-detected': 'No indicators detected',
  review: 'Review recommended',
  multiple: 'Multiple indicators',
  'high-risk': 'High risk',
  inconclusive: 'Inconclusive',
};
