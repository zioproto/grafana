import React from 'react';

import { Badge } from '@grafana/ui';

import { CatalogPlugin } from '../../types';

type Props = { plugin: CatalogPlugin };

export function PluginStateBadge({ plugin }: Props): React.ReactElement | null {
  if (plugin.isAlpha) {
    return <Badge text="Alpha" color="orange" />;
  } else if (plugin.isBeta) {
    return <Badge text="Beta" color="violet" />;
  } else {
    return null;
  }
}
