import { useState, useCallback, useEffect } from 'react';

export interface UseKeyboardNavigationOptions {
  readonly itemCount: number;
  readonly initialIndex?: number;
  readonly onSelect?: (index: number) => void;
  readonly onEscape?: () => void;
  readonly enabled?: boolean;
}

export interface UseKeyboardNavigationReturn {
  readonly selectedIndex: number;
  readonly setSelectedIndex: (index: number) => void;
  readonly handleKeyDown: (event: React.KeyboardEvent | KeyboardEvent) => void;
}

export function useKeyboardNavigation({
  itemCount,
  initialIndex = 0,
  onSelect,
  onEscape,
  enabled = true,
}: UseKeyboardNavigationOptions): UseKeyboardNavigationReturn {
  const [selectedIndex, setSelectedIndex] = useState<number>(initialIndex);

  // Keep index within bounds if itemCount shrinks
  useEffect(() => {
    if (itemCount === 0) {
      setSelectedIndex(-1);
    } else if (selectedIndex >= itemCount) {
      setSelectedIndex(itemCount - 1);
    } else if (selectedIndex < 0 && itemCount > 0) {
      setSelectedIndex(0);
    }
  }, [itemCount, selectedIndex]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent | KeyboardEvent) => {
      if (!enabled || itemCount === 0) return;

      switch (event.key) {
        case 'ArrowDown':
          event.preventDefault();
          setSelectedIndex((prev) => (prev + 1) % itemCount);
          break;

        case 'ArrowUp':
          event.preventDefault();
          setSelectedIndex((prev) => (prev <= 0 ? itemCount - 1 : prev - 1));
          break;

        case 'Home':
          event.preventDefault();
          setSelectedIndex(0);
          break;

        case 'End':
          event.preventDefault();
          setSelectedIndex(itemCount - 1);
          break;

        case 'Enter':
          if (selectedIndex >= 0 && selectedIndex < itemCount) {
            event.preventDefault();
            onSelect?.(selectedIndex);
          }
          break;

        case 'Escape':
          event.preventDefault();
          onEscape?.();
          break;

        default:
          break;
      }
    },
    [enabled, itemCount, onEscape, onSelect, selectedIndex]
  );

  return {
    selectedIndex,
    setSelectedIndex,
    handleKeyDown,
  };
}
