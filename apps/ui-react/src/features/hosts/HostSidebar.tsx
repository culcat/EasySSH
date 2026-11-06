import React, { useState, useMemo } from 'react';
import clsx from 'clsx';
import type { HostConfig, HostId } from '../../types/proto';
import { useI18n } from '../../i18n';
import { useKeyboardNavigation } from '../../hooks/useKeyboardNavigation';
import { Input, Button, Badge } from '../../ui';
import styles from './HostSidebar.module.css';

export interface HostSidebarProps {
  readonly hosts: readonly HostConfig[];
  readonly onConnect: (hostId: HostId) => void;
  readonly onAddHost?: () => void;
}

export const HostSidebar: React.FC<HostSidebarProps> = ({
  hosts,
  onConnect,
  onAddHost,
}) => {
  const { t } = useI18n();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);

  // Extract all unique tags
  const allTags = useMemo(() => {
    const set = new Set<string>();
    for (const host of hosts) {
      for (const tag of host.tags) {
        set.add(tag);
      }
    }
    return Array.from(set);
  }, [hosts]);

  // Filtered hosts based on search query and active tag filter
  const filteredHosts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return hosts.filter((host) => {
      const matchesTag = !selectedTag || host.tags.includes(selectedTag);
      if (!matchesTag) return false;

      if (!q) return true;
      return (
        host.label.toLowerCase().includes(q) ||
        host.hostname.toLowerCase().includes(q) ||
        host.username.toLowerCase().includes(q) ||
        host.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [hosts, searchQuery, selectedTag]);

  const { selectedIndex, setSelectedIndex, handleKeyDown } = useKeyboardNavigation({
    itemCount: filteredHosts.length,
    onSelect: (index) => {
      const targetHost = filteredHosts[index];
      if (targetHost) {
        onConnect(targetHost.id);
      }
    },
  });

  return (
    <aside className={styles.sidebar} aria-label={t('hosts.title')}>
      <div className={styles.header}>
        <div className={styles.titleRow}>
          <h1 className={styles.title}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
              <line x1="6" y1="6" x2="6.01" y2="6" />
              <line x1="6" y1="18" x2="6.01" y2="18" />
            </svg>
            {t('hosts.title')}
          </h1>
          {onAddHost && (
            <Button size="sm" variant="ghost" onClick={onAddHost} aria-label={t('hosts.addHost')}>
              +
            </Button>
          )}
        </div>

        <div className={styles.searchContainer}>
          <Input
            type="search"
            placeholder={t('hosts.searchPlaceholder')}
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
          />
        </div>

        {allTags.length > 0 && (
          <div className={styles.tagsContainer} role="toolbar" aria-label={t('hosts.tags')}>
            <button
              type="button"
              className={styles.tagFilterButton}
              onClick={() => setSelectedTag(null)}
            >
              <Badge variant={selectedTag === null ? 'info' : 'default'} size="sm">
                {t('hosts.allTags')}
              </Badge>
            </button>
            {allTags.map((tag) => (
              <button
                key={tag}
                type="button"
                className={styles.tagFilterButton}
                onClick={() => setSelectedTag(tag === selectedTag ? null : tag)}
              >
                <Badge variant={selectedTag === tag ? 'info' : 'default'} size="sm">
                  #{tag}
                </Badge>
              </button>
            ))}
          </div>
        )}
      </div>

      <ul
        className={styles.hostList}
        tabIndex={0}
        onKeyDown={handleKeyDown}
        role="listbox"
        aria-label={t('hosts.title')}
      >
        {filteredHosts.length === 0 ? (
          <li className={styles.emptyState}>
            {hosts.length === 0 ? t('hosts.noHostsFound') : t('hosts.noHostsMatching')}
          </li>
        ) : (
          filteredHosts.map((host, index) => {
            const isSelected = index === selectedIndex;
            return (
              <li
                key={host.id}
                role="option"
                aria-selected={isSelected}
                className={clsx(styles.hostItem, isSelected && styles.hostItemSelected)}
                onClick={() => {
                  setSelectedIndex(index);
                  onConnect(host.id);
                }}
              >
                <div className={styles.hostHeader}>
                  <span className={styles.hostLabel}>{host.label}</span>
                  <Badge variant="default" size="sm">
                    {host.authMethod}
                  </Badge>
                </div>

                <div className={styles.hostEndpoint}>
                  {host.username}@{host.hostname}:{host.port}
                </div>

                <div className={styles.hostFooter}>
                  <div className={styles.hostTags}>
                    {host.tags.map((tag) => (
                      <Badge key={tag} variant="default" size="sm">
                        #{tag}
                      </Badge>
                    ))}
                  </div>
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={(e) => {
                      e.stopPropagation();
                      onConnect(host.id);
                    }}
                  >
                    {t('common.connect')}
                  </Button>
                </div>
              </li>
            );
          })
        )}
      </ul>
    </aside>
  );
};
