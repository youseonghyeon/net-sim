import type { ActionSpec, Network } from "../network";

export interface NodeLayout {
  x: number;
  y: number;
}

export interface QuickAction {
  label: string;
  action: ActionSpec;
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
  build(): Network;
  layout: Record<string, NodeLayout>;
  quickActions: QuickAction[];
}
