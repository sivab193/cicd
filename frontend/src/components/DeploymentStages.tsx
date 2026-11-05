import {useState} from 'react';
import type {Item} from '../api';
import './deployment-stages.css';

type StageKey = 'build' | 'review' | 'security' | 'deploy' | 'verification';
type StageStatus = 'passed' | 'failed' | 'running' | 'pending' | 'upcoming';

const STAGES: {key: StageKey; label: string; step: string | null; note: string}[] = [
  {key: 'build', label: 'Build', step: 'build', note: 'Build step from deployment.steps.build.'},
  {key: 'review', label: 'Code review', step: null, note: 'No AI reviewer is connected. This stage is a UI placeholder only and does not approve, block, or change any deployment.'},
  {key: 'security', label: 'Security scan', step: 'security', note: 'Security scan step from deployment.steps.security.'},
  {key: 'deploy', label: 'Deploy', step: 'deploy', note: 'Deploy step from deployment.steps.deploy.'},
  {key: 'verification', label: 'Verification', step: 'verification', note: 'Verification step from deployment.steps.verification.'},
];

const ACTIVE = ['queued', 'building', 'deploying', 'verifying'];

function stageStatus(stage: (typeof STAGES)[number], deployment: Item): StageStatus {
  if (!stage.step) return 'upcoming';
  const raw = deployment.steps?.[stage.step];
  if (raw === 'passed' || raw === 'failed') return raw;
  if (!ACTIVE.includes(deployment.status)) return 'pending';
  // Running = the first mapped stage that has not passed yet, in stage order.
  for (const s of STAGES) {
    if (!s.step) continue;
    const v = deployment.steps?.[s.step];
    if (v === 'failed') return s.key === stage.key ? 'failed' : 'pending';
    if (v !== 'passed') return s.key === stage.key ? 'running' : 'pending';
  }
  return 'pending';
}

function marker(status: StageStatus, index: number) {
  if (status === 'passed') return '✓';
  if (status === 'failed') return '✕';
  if (status === 'running') return '…';
  return String(index + 1);
}

/**
 * Jenkins / Blue Ocean style stage view for one deployment.
 * Backend steps are build, security, deploy, verification. There is no
 * backend code-review step yet, so "Code review" is always shown as
 * upcoming, and the approval gate below it is a UI placeholder only:
 * it never calls an external AI API, stores no secrets, and never
 * blocks or approves a deployment.
 * Stage clicks only change the selected stage shown here. The
 * deployment logs shown by the parent are the shared deployment log:
 * the backend does not split logs per stage yet.
 */
export default function DeploymentStages({deployment, demo, onSelectStage}: {deployment: Item; demo: boolean; onSelectStage?: (key: StageKey) => void}) {
  const [selected, setSelected] = useState<StageKey>('build');
  const current = STAGES.find(s => s.key === selected) || STAGES[0];
  const currentStatus = stageStatus(current, deployment);
  const gateText = demo ? 'AI review: pending' : 'AI review: not connected yet';
  const pick = (key: StageKey) => {
    setSelected(key);
    onSelectStage?.(key);
  };
  return (
    <div className="deployment-stages">
      <div className="stage-strip" role="list" aria-label="Deployment stages">
        {STAGES.map((stage, i) => {
          const status = stageStatus(stage, deployment);
          return (
            <div className="stage-wrap" key={stage.key} role="listitem">
              <button
                type="button"
                className={`stage ${status} ${selected === stage.key ? 'selected' : ''}`}
                onClick={() => pick(stage.key)}
                aria-pressed={selected === stage.key}
              >
                <span className="stage-dot">{marker(status, i)}</span>
                <b>{stage.label}</b>
                <small>{status}</small>
              </button>
              {i < STAGES.length - 1 && <span className="stage-connector" aria-hidden="true" />}
            </div>
          );
        })}
      </div>
      <div className="approval-gate">
        <b>Approval gate</b>
        <span>{gateText}</span>
        <small>Upcoming — not enforced yet. No AI provider is connected and no approval is required or recorded.</small>
      </div>
      <div className="stage-detail">
        <b>{current.label}</b>
        <span className={`stage-status ${currentStatus}`}>{currentStatus}</span>
        <p>{current.note} Logs shown below are the shared deployment log; per-stage logs are not split in the backend yet.</p>
      </div>
    </div>
  );
}
