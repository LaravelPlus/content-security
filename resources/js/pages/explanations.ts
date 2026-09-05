/**
 * Kaj preverjanje isce in kaj njegova najdba pomeni.
 *
 * Zaslon je doslej pokazal ime podpisa (`file.embedded_php`) in stopnjo, kar
 * je za tistega, ki tega ni pisal, samo niz. Razlage stojijo tu enkrat, ker
 * jih bereta dva zaslona -- pregled in seznam najdb -- in bi se locena zapisa
 * razsla ze ob prvem popravku.
 */
export const checkExplanations: Record<string, string> = {
    size: 'The file is larger than the policy allows.',
    extension:
        'The extension is not on the policy list, or the name carries more than one.',
    mime: 'The declared type and the detected type disagree.',
    magic_bytes: 'The first bytes do not match the type the name claims.',
    archive: 'The archive holds something the policy refuses.',
    image: 'The image could not be decoded, or carries data after its end.',
    pdf: 'The document carries active content (scripts, embedded files, launch actions).',
    malware:
        'The malware engine reported a signature match, or could not answer.',
    length: 'The text is longer than the policy allows.',
    suspicious: 'The text carries patterns the policy treats as an attack.',
    html: 'The markup carried something the sanitizer removed.',
    urls: 'A link points somewhere the policy refuses.',
};

/** Kaj pomeni posamezna najdba, po imenu podpisa. */
export const threatExplanations: Record<string, string> = {
    'file.multiple_extensions':
        'The name carries more than one extension (invoice.pdf.exe). Also matches our own derived names, such as photo.256.webp.',
    'file.embedded_php':
        'PHP code was found inside a file that should hold none.',
    'file.embedded_script':
        'A script tag was found inside a file that should hold none.',
    'file.extension_not_allowed': 'The extension is not on the policy list.',
    'file.mime_mismatch': 'The declared type and the detected type disagree.',
    'file.too_large': 'The file is larger than the policy allows.',
    'file.image_undecodable':
        'The image could not be decoded — it is not the picture it claims to be.',
    'file.trailing_data': 'Something is appended after the end of the image.',
    'archive.path_traversal':
        'A path inside the archive escapes its own directory.',
    'archive.too_deep': 'The archive nests deeper than the policy allows.',
    'archive.bomb': 'The archive expands far beyond its compressed size.',
    'pdf.javascript': 'The document runs JavaScript when opened.',
    'pdf.embedded_file': 'The document carries another file inside it.',
    'pdf.launch_action': 'The document asks to launch a program.',
    'scan.check_failed':
        'A check could not complete, so the file is unproven rather than clean.',
    'text.injection': 'The text carries an injection pattern.',
    'url.blocked_host': 'A link points at a host the policy refuses.',
};

/**
 * Razlaga najdbe; neznan podpis pade nazaj na vir, ki ga je nasel.
 *
 * Podpisov protivirusnega pogona je milijon in imena so njegova, ne nasa --
 * zato tam povemo, kdo je nasel, ne kaj tocno je.
 */
export function explainThreat(name: string, source?: string | null): string {
    if (threatExplanations[name]) {
        return threatExplanations[name];
    }

    if (source === 'clamav' || source === 'malware') {
        return `The malware engine matched a known signature (${name}).`;
    }

    return (
        (source ? checkExplanations[source] : undefined) ??
        'The policy refused this content.'
    );
}
