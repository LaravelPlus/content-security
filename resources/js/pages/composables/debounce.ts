/**
 * Filters fire on every keystroke; without this the scans page would issue a
 * query per character typed.
 */
export function debounce<T extends (...args: never[]) => void>(
    callback: T,
    wait = 300,
): (...args: Parameters<T>) => void {
    let timer: ReturnType<typeof setTimeout> | undefined;

    return (...args: Parameters<T>): void => {
        if (timer !== undefined) {
            clearTimeout(timer);
        }

        timer = setTimeout(() => callback(...args), wait);
    };
}
