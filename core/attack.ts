// A small slice of the MITRE ATT&CK for Containers matrix — the techniques the
// NIGHTWATCH ruleset covers. Names/tactics are the public ATT&CK taxonomy.

import type { TechniqueInfo } from './types.ts';

export const TECHNIQUES: Record<string, TechniqueInfo> = {
  T1610: { id: 'T1610', name: 'Deploy Container', tactic: 'Defense Evasion / Execution' },
  T1611: { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation' },
  T1612: { id: 'T1612', name: 'Build Image on Host', tactic: 'Defense Evasion' },
  T1613: { id: 'T1613', name: 'Container & Resource Discovery', tactic: 'Discovery' },
  T1552: { id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access' },
  'T1552.007': { id: 'T1552.007', name: 'Container API / SA Token', tactic: 'Credential Access' },
  T1059: { id: 'T1059', name: 'Command & Scripting Interpreter', tactic: 'Execution' },
  T1071: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command & Control' },
  T1496: { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
  T1105: { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command & Control' },
  T1570: { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'Lateral Movement' },
  T1053: { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Persistence' },
  T1548: { id: 'T1548', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation' },
  T1078: { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
  T1222: { id: 'T1222', name: 'File & Directory Permissions Mod', tactic: 'Defense Evasion' },
  T1021: { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
};

export const TACTIC_ORDER = [
  'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
  'Credential Access', 'Discovery', 'Lateral Movement', 'Command & Control', 'Impact',
];

export function primaryTactic(info: TechniqueInfo): string {
  return info.tactic.split(' / ')[0];
}
