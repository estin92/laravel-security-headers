export function timestamp(iso: string): string {
    return iso.replace('T', ' ').replace('Z', ' UTC');
}
